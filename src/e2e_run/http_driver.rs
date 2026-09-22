use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::model::ResolvedProjectConfig;
use super::result::E2eResponseUnavailableReason;
use super::store;
use crate::motan::response_kind_status_code;
use crate::recorded_request::{RecordedHttpClient, target_uri};
use crate::recorder::HeaderMapSnapshot;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Debug, Serialize)]
struct ActualResponse {
    version: u8,
    request_sent_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_rules: Vec<crate::request_rules::RequestRuleObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_headers: Option<HeaderMapSnapshot>,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HeaderMapSnapshot>,
    body: CapturedBody,
}

#[derive(Debug, Serialize)]
struct CapturedBody {
    encoding: &'static str,
    data: String,
    truncated: bool,
}

pub(crate) async fn wait_until_ready(config: &ResolvedProjectConfig) -> Result<()> {
    let client = client();
    let readiness_uri = target_uri(&config.target_http_origin, &config.target_readiness_path)?;
    let deadline = tokio::time::Instant::now() + config.target_startup_timeout;
    let mut http_ready = !config.target_http_readiness_enabled;
    let mut motan_ready = config.target_motan_upstream.is_none();
    let mut last_http_error = "probe not attempted".to_string();
    let mut last_motan_error = "probe not attempted".to_string();
    loop {
        if !http_ready {
            let request = Request::builder()
                .method(Method::GET)
                .uri(readiness_uri.clone())
                .body(Full::new(Bytes::new()))?;
            match tokio::time::timeout(Duration::from_secs(2), client.request(request)).await {
                Ok(Ok(response))
                    if response.status().as_u16() == config.target_readiness_status =>
                {
                    http_ready = true;
                }
                Ok(Ok(response)) => last_http_error = format!("HTTP {}", response.status()),
                Ok(Err(error)) => last_http_error = error.to_string(),
                Err(_) => last_http_error = "probe timed out".to_string(),
            }
        }
        if !motan_ready {
            let upstream = config
                .target_motan_upstream
                .as_deref()
                .expect("Motan readiness is pending only when its upstream is configured");
            match crate::gateway::motan::ready::probe_once(
                upstream,
                config.target_motan_connect_timeout,
                config.target_motan_request_timeout,
                config.target_motan_limits,
            )
            .await
            {
                Ok(()) => motan_ready = true,
                Err(error) => last_motan_error = format!("{error:#}"),
            }
        }
        if http_ready && motan_ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            if !http_ready && config.target_motan_upstream.is_none() {
                bail!(
                    "target did not become ready at {} with status {} within {:?}: {}",
                    readiness_uri,
                    config.target_readiness_status,
                    config.target_startup_timeout,
                    last_http_error
                );
            }
            if http_ready && !motan_ready {
                bail!(
                    "target Motan endpoint {} did not become ready within {:?}: {}",
                    config.target_motan_upstream.as_deref().unwrap_or_default(),
                    config.target_startup_timeout,
                    last_motan_error
                );
            }
            bail!(
                "target enabled services did not all become ready within {:?}; HTTP: {}; Motan: {}",
                config.target_startup_timeout,
                if http_ready {
                    "ready"
                } else {
                    &last_http_error
                },
                if motan_ready {
                    "ready"
                } else {
                    &last_motan_error
                }
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) async fn capture_case(
    target_root: &Path,
    config: &ResolvedProjectConfig,
    request_path: &Path,
    actual_response_path: &Path,
) -> Result<()> {
    let request_bytes = tokio::fs::read(request_path).await?;
    let kind: RequestKind = serde_json::from_slice(&request_bytes)?;
    if kind.protocol_version.is_some() {
        return capture_motan_case(config, kind, actual_response_path).await;
    }
    let response = RecordedHttpClient::new(
        config.target_http_origin.clone(),
        config.target_request_timeout,
        config.target_max_response_bytes,
    )
    .with_request_rules(target_root, &config.replay_policy)?
    .send(request_path)
    .await?;
    let (encoding, data) = match std::str::from_utf8(&response.body) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", STANDARD.encode(&response.body)),
    };
    store::write_json(
        actual_response_path,
        &ActualResponse {
            version: 1,
            request_sent_at: response.request_sent_at,
            request_rules: response.request_rules,
            request_headers: Some(response.request_headers),
            status: response.status.as_u16(),
            headers: Some(response.headers),
            body: CapturedBody {
                encoding,
                data,
                truncated: false,
            },
        },
    )
}

pub(super) fn response_unavailable_reason(error: &anyhow::Error) -> E2eResponseUnavailableReason {
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

#[derive(Deserialize)]
struct RequestKind {
    #[serde(default)]
    protocol_version: Option<String>,
    #[serde(default)]
    frame: Option<RecordedFrame>,
}

#[derive(Deserialize)]
struct RecordedFrame {
    encoding: String,
    data: String,
    truncated: bool,
}

async fn capture_motan_case(
    config: &ResolvedProjectConfig,
    request: RequestKind,
    actual_response_path: &Path,
) -> Result<()> {
    let upstream = config
        .target_motan_upstream
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Motan case requires a configured target Motan endpoint"))?;
    let frame = request
        .frame
        .ok_or_else(|| anyhow::anyhow!("Motan request has no frame"))?;
    if frame.truncated {
        bail!("Motan request frame is truncated");
    }
    let raw = match frame.encoding.as_str() {
        "utf8" => frame.data.into_bytes(),
        "base64" => STANDARD.decode(frame.data)?,
        encoding => bail!("unsupported Motan request encoding {encoding:?}"),
    };
    let limits = motan_protocol::Limits::default();
    let motan_protocol::DecodeStatus::Complete(request) =
        motan_protocol::decode_frame(&raw, limits)?
    else {
        bail!("Motan request frame is incomplete");
    };
    let request_sent_at = chrono::Utc::now();
    let operation = async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream.write_all(&raw).await?;
        if request.flags.oneway() {
            return Ok((204, Vec::new()));
        }
        let mut decoder = motan_protocol::FrameDecoder::new(limits)?;
        let response = loop {
            if let Some(frame) = decoder.decode()? {
                break frame;
            }
            let read = stream.read_buf(decoder.buffer_mut()).await?;
            if read == 0 {
                bail!("target closed before returning a Motan response");
            }
        };
        if response.request_id != request.request_id || response.version != request.version {
            bail!("target returned a mismatched Motan response frame");
        }
        let status = response_kind_status_code(response.response_kind());
        Ok::<_, anyhow::Error>((status, response.raw().to_vec()))
    };
    let (status, body) = tokio::time::timeout(config.target_request_timeout, operation)
        .await
        .map_err(|_| anyhow::anyhow!("target Motan request timed out"))??;
    let (encoding, data) = match std::str::from_utf8(&body) {
        Ok(text) => ("utf8", text.to_owned()),
        Err(_) => ("base64", STANDARD.encode(&body)),
    };
    store::write_json(
        actual_response_path,
        &ActualResponse {
            version: 1,
            request_sent_at,
            request_rules: Vec::new(),
            request_headers: None,
            status,
            headers: None,
            body: CapturedBody {
                encoding,
                data,
                truncated: false,
            },
        },
    )
}

fn client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

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
    async fn motan_only_target_becomes_ready_from_a_heartbeat_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut decoder =
                motan_protocol::FrameDecoder::new(motan_protocol::Limits::default()).unwrap();
            let request = loop {
                if let Some(request) = decoder.decode().unwrap() {
                    break request;
                }
                assert!(stream.read_buf(decoder.buffer_mut()).await.unwrap() > 0);
            };
            assert!(request.flags.heartbeat());
            let response = motan_protocol::FrameBuilder::response(request.request_id)
                .heartbeat(true)
                .status(motan_protocol::ResponseStatus::Normal)
                .encode()
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let config = ResolvedProjectConfig {
            target_dockerfile: PathBuf::from("Dockerfile.e2e"),
            target_build_contexts: Vec::new(),
            target_startup: crate::startup::StartupConfig::default(),
            target_runtime_outputs: Vec::new(),
            target_http_origin: "http://127.0.0.1:1".to_string(),
            target_port: 1,
            target_http_readiness_enabled: false,
            target_motan_upstream: Some(address.to_string()),
            target_motan_connect_timeout: Duration::from_secs(1),
            target_motan_request_timeout: Duration::from_secs(1),
            target_motan_limits: motan_protocol::Limits::default(),
            target_readiness_path: "/healthz".to_string(),
            target_readiness_status: 404,
            target_startup_timeout: Duration::from_secs(1),
            target_request_timeout: Duration::from_secs(1),
            target_quality_gates: Vec::new(),
            process_outputs: Vec::new(),
            process_output_rules: Default::default(),
            target_max_response_bytes: 1024,
            breeze_container: None,
            replay_policy: PathBuf::from("replay.yaml"),
            replay_case_dependency_post_response_window: Duration::from_millis(10),
            max_failed_cases_per_api: crate::DEFAULT_MAX_FAILED_CASES_PER_API,
            replay_startup_timeout: Duration::from_secs(1),
            pr_base: "main".to_string(),
            managed_paths: Vec::new(),
            recorder_config: PathBuf::from("project.yaml"),
            source_traffic_policy: PathBuf::from("source-traffic-policy.yaml"),
            runner_owned_response_assertions: true,
        };

        wait_until_ready(&config).await.unwrap();
        server.await.unwrap();
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
                .send(&request_path)
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
}
