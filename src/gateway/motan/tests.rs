use std::path::{Path, PathBuf};
use std::time::Duration;

use motan_protocol::{
    FrameBuilder, FrameDecoder, Limits, META_GROUP, META_METHOD, META_METHOD_DESC, META_PATH,
    MessageKind, Metadata, ProtocolVersion, encode_empty_response, parse_frame_ref,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::*;

const MOTAN1_REQUEST: &[u8] =
    include_bytes!("../../../../breeze/motan/interop/golden/motan1-request.bin");

#[tokio::test]
async fn matched_motan1_and_motan2_requests_are_forwarded_and_published() {
    let limits = Limits::default();
    let (upstream, source) = fixed_response_source(2, limits).await;
    let (temp, state, listen, gateway) = gateway_state(upstream.to_string(), Vec::new()).await;
    let mut client = connect_retry(listen).await;

    let motan1 = round_trip(&mut client, MOTAN1_REQUEST, limits).await;
    assert_eq!(motan1.version, ProtocolVersion::Motan1);
    assert_eq!(motan1.kind, MessageKind::Response);

    let motan2_request = motan2_request(91);
    let motan2 = round_trip(&mut client, &motan2_request, limits).await;
    assert_eq!(motan2.version, ProtocolVersion::Motan2);
    assert_eq!(motan2.kind, MessageKind::Response);
    assert_eq!(motan2.request_id, 91);

    source.await.unwrap();
    let cases = published_case_dirs(&state.recorder().run_dir);
    assert_eq!(cases.len(), 2);
    let mut versions = cases
        .iter()
        .map(|case| {
            read_json(case.join("request.json"))["protocol_version"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();
    versions.sort();
    assert_eq!(versions, ["motan1", "motan2"]);
    for published in cases {
        let request = read_json(published.join("request.json"));
        assert_eq!(request["method"], "MOTAN");
        assert_eq!(request["uri"], request["api_pattern"]);
        assert!(
            request["api_pattern"]
                .as_str()
                .unwrap()
                .starts_with("/rpc/")
        );
        let descriptor = read_json(published.join("case.json"));
        assert_eq!(descriptor["kind"], "motan_rpc");
        assert!(
            descriptor["api_key"]
                .as_str()
                .unwrap()
                .starts_with("motan:motan-rust-interop/")
        );
        assert!(published.join("expected-response.json").is_file());
        assert!(published.join("dependencies.jsonl").is_file());
    }

    gateway.abort();
    drop(client);
    drop(temp);
}

#[tokio::test]
async fn unmatched_motan1_and_motan2_requests_receive_fixed_responses_without_cases() {
    let rule = crate::config::MotanGatewayRuleConfig {
        apis: vec!["com.example.DoesNotMatch#call(void)".to_string()],
        ..Default::default()
    };
    let (temp, state, listen, gateway) = gateway_state("127.0.0.1:9".to_string(), vec![rule]).await;
    let limits = Limits::default();
    let mut client = connect_retry(listen).await;

    let motan1 = round_trip(&mut client, MOTAN1_REQUEST, limits).await;
    assert_eq!(motan1.version, ProtocolVersion::Motan1);
    assert_eq!(motan1.kind, MessageKind::Response);
    assert!(motan1.body.is_empty());

    let motan2_request = motan2_request(92);
    let motan2 = round_trip(&mut client, &motan2_request, limits).await;
    assert_eq!(motan2.version, ProtocolVersion::Motan2);
    assert_eq!(motan2.kind, MessageKind::Response);
    assert_eq!(motan2.request_id, 92);
    assert!(motan2.body.is_empty());
    assert!(published_case_dirs(&state.recorder().run_dir).is_empty());

    gateway.abort();
    drop(client);
    drop(temp);
}

#[tokio::test]
async fn overlapping_matched_request_uses_fixed_response_and_is_not_forwarded() {
    let limits = Limits::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (received, received_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut decoder = FrameDecoder::new(limits).unwrap();
        let request = transport::read_frame(&mut stream, &mut decoder, limits)
            .await
            .unwrap()
            .unwrap();
        received.send(()).unwrap();
        release_rx.await.unwrap();
        let request = parse_frame_ref(request.raw(), limits).unwrap();
        let mut response = Vec::new();
        encode_empty_response(request, &mut response, limits).unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let (temp, state, listen, gateway) = gateway_state(upstream.to_string(), Vec::new()).await;
    let mut first_client = connect_retry(listen).await;
    let first =
        tokio::spawn(
            async move { round_trip(&mut first_client, &motan2_request(101), limits).await },
        );
    received_rx.await.unwrap();

    let mut overlapping_client = connect_retry(listen).await;
    let overlapping = round_trip(&mut overlapping_client, &motan2_request(102), limits).await;
    assert_eq!(overlapping.request_id, 102);
    assert!(overlapping.body.is_empty());
    assert!(published_case_dirs(&state.recorder().run_dir).is_empty());

    release.send(()).unwrap();
    assert_eq!(first.await.unwrap().request_id, 101);
    source.await.unwrap();
    assert_eq!(published_case_dirs(&state.recorder().run_dir).len(), 1);

    gateway.abort();
    drop(overlapping_client);
    drop(temp);
}

#[tokio::test]
async fn http_and_motan_share_one_process_wide_case_slot() {
    let limits = Limits::default();
    let (temp, state, listen, gateway) = gateway_state("127.0.0.1:9".to_string(), Vec::new()).await;
    let http_case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "http-api".to_string(),
        uri_group: Some("api/http".to_string()),
    };
    let http_guard = state.try_reserve_active_case(http_case).unwrap();
    let mut client = connect_retry(listen).await;

    let response = round_trip(&mut client, &motan2_request(103), limits).await;

    assert_eq!(response.request_id, 103);
    assert!(response.body.is_empty());
    assert!(published_case_dirs(&state.recorder().run_dir).is_empty());

    drop(http_guard);
    gateway.abort();
    drop(client);
    drop(temp);
}

#[tokio::test]
async fn gateway_failures_are_persisted_as_preflight_evidence() {
    let (temp, state, _listen, gateway) =
        gateway_state("127.0.0.1:9".to_string(), Vec::new()).await;

    record_gateway_error(
        &state,
        Some("127.0.0.1:12345".to_string()),
        "bad Motan frame".to_string(),
    )
    .await
    .unwrap();
    state.recorder().flush_traffic().await.unwrap();

    let traffic = std::fs::read_to_string(state.recorder().run_dir.join("traffic.jsonl")).unwrap();
    assert!(traffic.contains(r#""protocol":"motan_gateway""#));
    assert!(traffic.contains("bad Motan frame"));

    gateway.abort();
    drop(temp);
}

async fn gateway_state(
    upstream: String,
    rules: Vec<crate::config::MotanGatewayRuleConfig>,
) -> (
    TempDir,
    AppState,
    std::net::SocketAddr,
    tokio::task::JoinHandle<Result<()>>,
) {
    let temp = tempfile::tempdir().unwrap();
    let listen = unused_address().await;
    let mut config = crate::AppConfig::default();
    config.mysql.enabled = false;
    config.motan_gateway.enabled = true;
    config.motan_gateway.listen = listen;
    config.motan_gateway.matched_upstream = upstream;
    config.motan_gateway.rules = rules;
    config.motan_gateway.max_frame_bytes = Limits::default().max_frame_bytes;
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.case_dependency_drain_timeout_ms = 100;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let gateway_state = state.clone();
    let gateway = tokio::spawn(async move { run(gateway_state).await });
    (temp, state, listen, gateway)
}

async fn fixed_response_source(
    requests: usize,
    limits: Limits,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut decoder = FrameDecoder::new(limits).unwrap();
            let request = transport::read_frame(&mut stream, &mut decoder, limits)
                .await
                .unwrap()
                .unwrap();
            let request_ref = parse_frame_ref(request.raw(), limits).unwrap();
            let mut response = Vec::new();
            encode_empty_response(request_ref, &mut response, limits).unwrap();
            if !response.is_empty() {
                stream.write_all(&response).await.unwrap();
            }
        }
    });
    (address, task)
}

async fn round_trip(
    stream: &mut TcpStream,
    request: &[u8],
    limits: Limits,
) -> motan_protocol::Frame {
    stream.write_all(request).await.unwrap();
    let mut decoder = FrameDecoder::new(limits).unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        transport::read_frame(stream, &mut decoder, limits),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap()
}

fn motan2_request(request_id: u64) -> Vec<u8> {
    let mut metadata = Metadata::new();
    metadata.insert(META_GROUP, "motan-rust-interop");
    metadata.insert(META_PATH, "com.weibo.breeze.motan.EchoService");
    metadata.insert(META_METHOD, "echo");
    metadata.insert(META_METHOD_DESC, "java.lang.String");
    FrameBuilder::request(request_id)
        .serialization(0)
        .metadata(metadata)
        .encode()
        .unwrap()
        .to_vec()
}

async fn unused_address() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn connect_retry(address: std::net::SocketAddr) -> TcpStream {
    for _ in 0..100 {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("Motan gateway {address} did not start");
}

fn published_case_dirs(run_dir: &Path) -> Vec<PathBuf> {
    fn walk(directory: &Path, cases: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path.join("case.json").is_file() && path.join("request.json").is_file() {
                cases.push(path);
            } else {
                walk(&path, cases);
            }
        }
    }
    let mut cases = Vec::new();
    walk(run_dir, &mut cases);
    cases
}

fn read_json(path: impl AsRef<Path>) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
