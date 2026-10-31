//! Exercise the real recording gateway and replay driver against independent peers.

mod binary;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::{BodyExt as _, Full};
use hyper::Request;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::Value;
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_tungstenite::tungstenite::Message;

use crate::interaction::{
    model::{InputTranscript, OutputObservation, Protocol},
    policy::{CompletionRule, EventCompletion, InteractionPolicy},
};

mod cancellation;
mod content_type;
mod dependency_tail;
mod polling;
mod recovery;
mod reuse;
mod server_close;
mod subscription;
use crate::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayRuleConfig,
};

fn config(temp: &Path, upstream: SocketAddr) -> AppConfig {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    std::fs::create_dir_all(temp.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(temp).unwrap();
    let mut config = AppConfig::default();
    config.http_gateway.enabled = true;
    config.http_gateway.matched_upstream = format!("http://{upstream}");
    config.http_gateway.record_streaming = true;
    config.http_gateway.request_timeout_ms = 1_000;
    config.http_gateway.interaction = InteractionPolicy {
        business_idle_ms: 90,
        max_duration_ms: 3_000,
        request_timeout_ms: 1_000,
        cleanup_timeout_ms: 1_000,
        input_gap_ms: 1,
        completion: vec![EventCompletion {
            namespace: "/".into(),
            event: "ask".into(),
            completion: CompletionRule::Ack,
        }],
        ..Default::default()
    };
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("interaction".into()),
        methods: vec!["GET".into(), "POST".into()],
        path_prefixes: vec!["/".into()],
        ..Default::default()
    }];
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
    config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
        status: 200,
        body: "busy".into(),
        ..Default::default()
    });
    config.mysql.enabled = false;
    config.recording.output_dir = temp.join(".traffic-e2e/local/artifacts/recordings");
    config.tls.ca_cert_path = temp.join("ca.pem");
    config.tls.ca_key_path = temp.join("ca-key.pem");
    config
}

async fn gateway(state: AppState) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        super::super::run_with_listener(state, listener)
            .await
            .unwrap();
    });
    (address, task)
}

async fn published(state: &AppState) -> PathBuf {
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await,
        "case guard did not release after the post-response dependency window"
    );
    state.recorder().flush_traffic().await.unwrap();
    let mut cases = Vec::new();
    find_cases(&state.recorder().run_dir.join("apis"), &mut cases);
    assert_eq!(
        cases.len(),
        1,
        "exactly one connection-scoped case should publish"
    );
    cases.pop().unwrap()
}

fn find_cases(directory: &Path, cases: &mut Vec<PathBuf>) {
    if directory.join("expected-response.json").is_file() {
        cases.push(directory.to_owned());
        return;
    }
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                find_cases(&entry.path(), cases);
            }
        }
    }
}

async fn replay_case(case: &Path, target: SocketAddr) -> OutputObservation {
    let request_json: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    let transcript: InputTranscript =
        serde_json::from_value(request_json["interaction"].clone()).unwrap();
    let origin = format!("http://{target}");
    let request = Request::builder()
        .method(request_json["method"].as_str().unwrap())
        .uri(
            crate::recorded_request::target_uri(&origin, request_json["uri"].as_str().unwrap())
                .unwrap(),
        )
        .body(Full::new(Bytes::new()))
        .unwrap();
    let client = Client::builder(TokioExecutor::new()).build_http();
    let replay = timeout(
        Duration::from_secs(3),
        crate::interaction::replay::execute(
            &client,
            &origin,
            request,
            &transcript,
            Duration::from_secs(1),
            1024 * 1024,
            Default::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let actual = case.join("test-actual.json");
    std::fs::write(
        &actual,
        serde_json::to_vec(&serde_json::json!({
            "version": 1, "request_sent_at": chrono::Utc::now(), "status": replay.status.as_u16(),
            "headers": replay.headers, "body": {"encoding":"utf8", "data":"", "truncated":false},
            "interaction": replay.observation,
        }))
        .unwrap(),
    )
    .unwrap();
    let policy = case.join("test-policy.yaml");
    crate::replay::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let report = crate::replay::assert_recorded_response(crate::replay::ResponseAssertionOptions {
        case_id: "recording-self-replay".into(),
        request: case.join("request.json"),
        expected_response: case.join("expected-response.json"),
        actual_response: actual,
        policy,
    })
    .unwrap();
    assert!(
        report.passed,
        "Source recording did not self-replay: {:?}; actual end: {:?}; actual events: {}",
        report.differences,
        replay.observation.end,
        replay.observation.events.len()
    );
    replay.observation
}

async fn websocket_peer(listener: TcpListener, sid: &'static str) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            format!(
                "0{{\"sid\":\"{sid}\",\"upgrades\":[],\"pingInterval\":20,\"pingTimeout\":1000}}"
            )
            .into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "40"
    );
    socket
        .send(Message::Text(
            format!("40{{\"sid\":\"{sid}-namespace\"}}").into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "427[\"ask\",1]"
    );
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "428[\"ask\",2]"
    );
    socket.send(Message::Text("438[2]".into())).await.unwrap();
    socket.send(Message::Text("437[1]".into())).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "429[\"ask\",3]"
    );
    socket.send(Message::Text("439[3]".into())).await.unwrap();
    let mut pings = tokio::time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            _ = pings.tick() => { if socket.send(Message::Text("2live".into())).await.is_err() { break; } }
            message = socket.next() => match message {
                Some(Ok(Message::Text(text))) if text == "3live" => {},
                Some(Ok(Message::Text(text))) if text == "1" => break,
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                message => panic!("unexpected client message: {message:?}"),
            }
        }
    }
}

#[tokio::test]
async fn one_socket_records_overlapping_and_serial_ack_interactions_then_self_replays() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut settings = config(temp.path(), upstream.local_addr().unwrap());
    // This checks ACK causality, not the short idle deadline used by other
    // fixtures. A fresh Target handshake may use its full one-second allowance
    // before any business input becomes pending during parallel test execution.
    settings.http_gateway.interaction.business_idle_ms = 1_000;
    let state = AppState::new(settings).await.unwrap();
    let source = tokio::spawn(websocket_peer(upstream, "source"));
    let (address, recording) = gateway(state.clone()).await;
    let (mut client, _) = tokio_tungstenite::connect_async(format!(
        "ws://{address}/socket.io/?EIO=4&transport=websocket"
    ))
    .await
    .unwrap();
    assert!(
        client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with('0')
    );
    client.send(Message::Text("40".into())).await.unwrap();
    assert!(
        client
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap()
            .starts_with("40")
    );
    client
        .send(Message::Text("427[\"ask\",1]".into()))
        .await
        .unwrap();
    client
        .send(Message::Text("428[\"ask\",2]".into()))
        .await
        .unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        "438[2]"
    );
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        "437[1]"
    );
    client
        .send(Message::Text("429[\"ask\",3]".into()))
        .await
        .unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        "439[3]"
    );
    timeout(Duration::from_secs(2), async {
        loop {
            match client.next().await {
                Some(Ok(Message::Text(text))) if text == "2live" => {
                    client.send(Message::Text("3live".into())).await.unwrap()
                }
                Some(Ok(Message::Close(_))) | None => break,
                message => panic!("unexpected recording message: {message:?}"),
            }
        }
    })
    .await
    .unwrap();
    source.await.unwrap();
    let case = published(&state).await;
    let input: Value = serde_json::from_slice(
        &crate::request_headers::load_request_file(&case.join("request.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(input["interaction"]["protocol"], "socket_io");
    let actions = input["interaction"]["actions"].as_array().unwrap();
    assert!(
        actions
            .iter()
            .any(|action| action["compressible_gap"] == true)
    );
    assert!(actions.iter().any(
        |action| action["action"]["message"]["data"] == "428[\"ask\",2]"
            && action["compressible_gap"] == false
    ));
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target = tokio::spawn(websocket_peer(target_listener, "target-different-sid"));
    let actual = replay_case(&case, target_addr).await;
    assert!(actual.end.clean);
    target.await.unwrap();
    recording.abort();
}

async fn read_head(stream: &mut tokio::net::TcpStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
}

#[tokio::test]
async fn sse_first_event_forwards_before_eof_and_ndjson_autodetection_self_replays() {
    for protocol in [Protocol::Sse, Protocol::Ndjson] {
        let temp = tempdir().unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
            .await
            .unwrap();
        let (release, released) = oneshot::channel();
        let (content, first, second) = if protocol == Protocol::Sse {
            ("text/event-stream", "data: first\n\n", "data: second\n\n")
        } else {
            ("application/x-ndjson", "{\"n\":1}\n", "{\"n\":2}\n")
        };
        let source = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_head(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n", first.len()).as_bytes()).await.unwrap();
            released.await.unwrap();
            stream
                .write_all(format!("{:x}\r\n{second}\r\n0\r\n\r\n", second.len()).as_bytes())
                .await
                .unwrap();
        });
        let (address, recording) = gateway(state.clone()).await;
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let request = Request::builder()
            .uri(format!("http://{address}/events"))
            .header("accept", format!("application/json, {content}"));
        let response = client
            .request(request.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let mut body = response.into_body();
        let first_frame = timeout(Duration::from_millis(500), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            first_frame.data_ref().unwrap().as_ref(),
            first.as_bytes(),
            "Recorder must deliver the first event while Source is waiting"
        );
        release.send(()).unwrap();
        assert_eq!(
            body.collect().await.unwrap().to_bytes().as_ref(),
            second.as_bytes()
        );
        source.await.unwrap();
        let case = published(&state).await;
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            read_head(&mut stream).await;
            let all = format!("{first}{second}");
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content}\r\nContent-Length: {}\r\n\r\n{all}", all.len()).as_bytes()).await.unwrap();
        });
        assert_eq!(replay_case(&case, target_addr).await.protocol, protocol);
        target.await.unwrap();
        recording.abort();
    }
}
