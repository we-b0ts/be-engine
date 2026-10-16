//! Exercise Source ownership through the real HTTP recorder and published cases.
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use traffic_e2e::{AppConfig, AppState, RecordingAccessPolicy};

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test]
async fn real_recording_separates_static_sources_and_combines_only_confirmed_methods() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempfile::tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let source = tokio::spawn(async move {
        for _ in 0..5 {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                let size = stream.read(&mut chunk).await.unwrap();
                assert!(size > 0, "Source connection ended before complete headers");
                request.extend_from_slice(&chunk[..size]);
                assert!(request.len() <= 4096);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    let addr = free_addr();
    let mut config = AppConfig::default();
    config.http.enabled = false;
    config.mysql.enabled = false;
    config.http_gateway.enabled = true;
    config.http_gateway.listen = addr;
    config.http_gateway.matched_upstream = format!("http://{upstream_addr}");
    config.http_gateway.source_routes = vec![
        "GET /objects/*".into(),
        "POST /objects/*".into(),
        "POST /objects/upload".into(),
    ]
    .try_into()
    .unwrap();
    // A stale methodless hint must not authorize DELETE or absorb the static POST.
    config.http_gateway.case_path_patterns = vec!["/objects/*".into()];
    config.recording.access_policy = RecordingAccessPolicy::Unrestricted;
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.case_dependency_post_response_window_ms = 0;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let recorder = state.recorder().clone();
    let server = tokio::spawn(async move { state.run().await });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for (method, path) in [
        ("GET", "/objects/7"),
        ("POST", "/objects/7"),
        ("GET", "/objects/upload"),
        ("POST", "/objects/upload"),
        ("DELETE", "/objects/upload"),
    ] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
    }
    source.await.unwrap();
    recorder.flush_traffic().await.unwrap();
    let run = std::fs::read_dir(temp.path().join("recordings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut groups = BTreeMap::new();
    for entry in std::fs::read_dir(run.join("apis")).unwrap() {
        let directory = entry.unwrap().path();
        let mut requests = Vec::new();
        for case in std::fs::read_dir(&directory).unwrap() {
            let request: Value = serde_json::from_slice(
                &std::fs::read(case.unwrap().path().join("request.json")).unwrap(),
            )
            .unwrap();
            requests.push((
                request["method"].as_str().unwrap().to_string(),
                request["api_pattern"].as_str().unwrap().to_string(),
            ));
        }
        groups.insert(directory, requests);
    }
    assert_eq!(groups.len(), 3);
    let dynamic = groups
        .values()
        .find(|requests| requests.len() == 3)
        .unwrap();
    assert!(dynamic.iter().all(|(_, pattern)| pattern == "/objects/*"));
    assert_eq!(
        dynamic.iter().filter(|(method, _)| method == "GET").count(),
        2
    );
    assert_eq!(
        dynamic
            .iter()
            .filter(|(method, _)| method == "POST")
            .count(),
        1
    );
    let singletons = groups
        .values()
        .filter(|requests| requests.len() == 1)
        .collect::<Vec<_>>();
    assert_eq!(singletons.len(), 2);
    assert!(
        singletons
            .iter()
            .any(|r| r[0] == ("POST".into(), "/objects/upload".into()))
    );
    assert!(
        singletons
            .iter()
            .any(|r| r[0] == ("DELETE".into(), "/objects/upload".into()))
    );
    server.abort();
}
