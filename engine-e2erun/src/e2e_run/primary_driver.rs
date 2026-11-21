//! Primary input orchestration delegates protocol I/O to static native adapters.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use super::active_artifact;
use super::model::ResolvedProjectConfig;
use super::result::E2eResponseUnavailableReason;
use crate::primary_protocol::{
    CaseExecutionContext, ExecutionSettings, NativePrimaryAdapter, PrimaryProtocol,
};
use crate::recorded_request::target_uri;
use crate::request_rules::RequestRuleRuntime;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub(crate) async fn wait_until_ready(config: &ResolvedProjectConfig) -> Result<()> {
    if !config.target_http_readiness_enabled {
        return Ok(());
    }
    let client = client();
    let readiness_uri = target_uri(&config.target_http_origin, &config.target_readiness_path)?;
    let deadline = tokio::time::Instant::now() + config.target_startup_timeout;
    loop {
        let request = Request::builder()
            .method(Method::GET)
            .uri(readiness_uri.clone())
            .body(Full::new(Bytes::new()))?;
        let reason = match tokio::time::timeout(Duration::from_secs(2), client.request(request))
            .await
        {
            Ok(Ok(response)) if response.status().as_u16() == config.target_readiness_status => {
                return Ok(());
            }
            Ok(Ok(response)) => format!("HTTP {}", response.status()),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "probe timed out".to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "target did not become ready at {} with status {} within {:?}: {}",
                readiness_uri,
                config.target_readiness_status,
                config.target_startup_timeout,
                reason
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) async fn capture_case(
    config: &ResolvedProjectConfig,
    request_path: &Path,
    request_bytes: &[u8],
    actual_response_path: &Path,
    request_rules: Arc<RequestRuleRuntime>,
    input_registration: (&Path, &str),
    fast_case_deadline: Option<tokio::time::Instant>,
) -> Result<Vec<u8>> {
    let input = PrimaryProtocol::from_recorded(request_bytes)?;
    let monitor =
        super::request_feedback::Monitor::start(input_registration.0, input_registration.1);
    let request_timeout = if input.has_interaction() {
        config.target_request_timeout
    } else {
        super::source_response::request_timeout(
            request_path
                .parent()
                .context("request has no case directory")?,
            config.target_request_timeout,
        )?
    };
    let context = CaseExecutionContext {
        case_id: input_registration.1,
        session_path: input_registration.0,
        request_path,
        request_rules,
        dependency_failure: Some(monitor.receiver()),
        settings: ExecutionSettings {
            http_origin: &config.target_http_origin,
            request_timeout,
            max_response_bytes: config.target_max_response_bytes,
            socketio_timing: config.replay_socketio_timing,
        },
        deadline: tokio::time::Instant::now() + request_timeout,
    };
    let execution = input.execute(&context);
    let output = match fast_case_deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, execution)
            .await
            .context("fast replay case exceeded its 120-second execution budget")??,
        None => execution.await?,
    };
    active_artifact::write_json(actual_response_path, &output.artifact()?)
}

pub(super) fn response_unavailable_reason(error: &anyhow::Error) -> E2eResponseUnavailableReason {
    if error.is::<crate::dependency::execution::UnmatchedDependency>() {
        return E2eResponseUnavailableReason::DependencyUnmatched;
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<hyper::Error>()
            .is_some_and(|error| error.is_incomplete_message() || error.is_closed())
    }) || error
        .chain()
        .any(|cause| cause.to_string() == "target closed before returning a Motan response")
    {
        return E2eResponseUnavailableReason::TargetConnectionClosed;
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<hyper_util::client::legacy::Error>()
            .is_some_and(hyper_util::client::legacy::Error::is_connect)
    }) {
        return E2eResponseUnavailableReason::TargetConnectionFailed;
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }) || error
        .chain()
        .any(|cause| cause.to_string() == "target Motan request timed out")
    {
        return E2eResponseUnavailableReason::TargetRequestTimedOut;
    }
    if error
        .chain()
        .any(|cause| cause.to_string() == "failed to read recorded HTTP response body")
    {
        return E2eResponseUnavailableReason::TargetResponseReadFailed;
    }
    if error.chain().any(|cause| {
        let message = cause.to_string();
        message.starts_with("failed to prepare replay request")
            || message.starts_with("invalid recorded request")
    }) {
        return E2eResponseUnavailableReason::RequestPreparationFailed;
    }
    E2eResponseUnavailableReason::HttpExecutionFailed
}

fn client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    connector.set_nodelay(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::recorded_request::RecordedHttpClient;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn target_readiness_uri_is_retargeted() {
        assert_eq!(
            target_uri("http://127.0.0.1:8081", "/healthz")
                .unwrap()
                .to_string(),
            "http://127.0.0.1:8081/healthz"
        );
    }

    #[tokio::test]
    async fn classifies_target_close_before_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let request_path = temp.path().join("request.json");
        std::fs::write(
            &request_path,
            br#"{"method":"GET","uri":"/api","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}}"#,
        )
        .unwrap();

        let result =
            RecordedHttpClient::new(format!("http://{address}"), Duration::from_secs(2), 1024)
                .send_bytes(&std::fs::read(&request_path).unwrap(), "recorded request")
                .await;
        let error = match result {
            Ok(_) => panic!("target close must fail the recorded HTTP request"),
            Err(error) => error,
        };
        server.await.unwrap();

        assert_eq!(
            response_unavailable_reason(&error),
            E2eResponseUnavailableReason::TargetConnectionClosed
        );
    }

    #[tokio::test]
    async fn fast_case_deadline_cancels_an_open_websocket() {
        use crate::interaction::{
            model::{InputTranscript, Protocol},
            policy::{InteractionPolicy, StreamTerminal},
        };
        use futures_util::StreamExt;
        use serde_json::json;
        use tokio::time::{Instant, advance, pause};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().to_path_buf();
        let mut config = super::super::test_session::config(&root);
        std::fs::write(
            &config.replay_policy,
            "format: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        let request_rules =
            Arc::new(RequestRuleRuntime::load(&root, &config.replay_policy).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.target_http_origin = format!("http://{}", listener.local_addr().unwrap());
        config.target_request_timeout = Duration::from_secs(900);
        let request = json!({
            "method": "GET", "uri": "/socket", "headers": {},
            "body": {"encoding": "utf8", "data": "", "truncated": false},
            "interaction": InputTranscript::new(Protocol::WebSocket, InteractionPolicy {
                business_idle_ms: 600_000,
                stream_terminal: Some(StreamTerminal::Text { value: "done".into() }),
                ..InteractionPolicy::default()
            })
        })
        .to_string();
        let (connected, handshake) = tokio::sync::oneshot::channel();
        let target = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            connected.send(()).unwrap();
            // There is no application response or server close.
            assert!(socket.next().await.is_none_or(|frame| frame.is_err()));
        });
        let deadline = Instant::now() + crate::replay::FAST_CASE_TIMEOUT;
        let mut replay = tokio::spawn(async move {
            capture_case(
                &config,
                &root.join("request.json"),
                request.as_bytes(),
                &root.join("actual-response.json"),
                request_rules,
                (&root.join("session.json"), "case"),
                Some(deadline),
            )
            .await
        });
        tokio::select! {
            result = &mut replay => panic!("replay ended before the WebSocket opened: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(3), handshake) => {
                result.unwrap().unwrap();
            }
        }
        pause();
        advance(deadline - Instant::now() - Duration::from_millis(10)).await;
        assert!(!replay.is_finished());
        advance(Duration::from_millis(10)).await;
        let error = replay.await.unwrap().unwrap_err();
        assert_eq!(
            response_unavailable_reason(&error),
            E2eResponseUnavailableReason::TargetRequestTimedOut
        );
        assert!(error.to_string().contains("120-second execution budget"));
        target.await.unwrap();
    }
}
