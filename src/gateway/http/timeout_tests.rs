use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::{
    AppConfig, AppState, HttpGatewayFallbackMode, HttpGatewayFixedResponseConfig,
    HttpGatewayRuleConfig,
};

mod fixtures;
use fixtures::{MysqlClient, gateway, get, reply, request};

fn config(temp: &std::path::Path, upstream: std::net::SocketAddr) -> AppConfig {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut config = AppConfig::default();
    config.http_gateway.enabled = true;
    config.http_gateway.matched_upstream = format!("http://{upstream}");
    config.http_gateway.request_timeout_ms = 1_000;
    config.http_gateway.fallback_mode = HttpGatewayFallbackMode::FixedResponse;
    config.http_gateway.fixed_response = Some(HttpGatewayFixedResponseConfig {
        status: 200,
        body: "busy".into(),
        ..Default::default()
    });
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("record".into()),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/record/".into()],
        ..Default::default()
    }];
    config.mysql.enabled = false;
    config.recording.case_dependency_post_response_window_ms = 20;
    config.recording.output_dir = temp.join("recordings");
    config.tls.ca_cert_path = temp.join("ca.pem");
    config.tls.ca_key_path = temp.join("ca-key.pem");
    config
}

#[tokio::test]
async fn timeout_before_headers_keeps_late_mysql_out_of_the_next_case() {
    isolation(false).await;
}

#[tokio::test]
async fn timeout_during_body_keeps_late_mysql_out_of_the_next_case() {
    isolation(true).await;
}

async fn isolation(body_timeout: bool) {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
        .await
        .unwrap();
    let source_state = state.clone();
    let (old_query_tx, old_query_rx) = oneshot::channel();
    let (late_query_tx, late_query_rx) = oneshot::channel();
    let (continue_tx, continue_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        request(&mut stream).await;
        if body_timeout {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        let mut mysql = MysqlClient::connect(source_state.clone()).await;
        mysql.query("SELECT 'old_before_timeout'").await;
        old_query_tx.send(()).unwrap();
        // The primary HTTP transport stays alive; only dependency sockets close.
        assert_eq!(mysql.stream.read(&mut [0]).await.unwrap(), 0);
        mysql.close().await;
        continue_rx.await.unwrap();
        let mut mysql = MysqlClient::connect(source_state.clone()).await;
        mysql.query("SELECT 'old_after_timeout'").await;
        late_query_tx.send(()).unwrap();
        finish_rx.await.unwrap();
        mysql.close().await;
        if body_timeout {
            stream.write_all(b"done").await.unwrap();
        } else {
            reply(&mut stream, "done").await;
        }
        drop(stream);
        let (mut stream, _) = upstream.accept().await.unwrap();
        request(&mut stream).await;
        let mut mysql = MysqlClient::connect(source_state).await;
        mysql.query("SELECT 'new_request'").await;
        mysql.close().await;
        reply(&mut stream, "fresh").await;
    });
    let (addr, server) = gateway(state.clone()).await;
    let first = tokio::spawn(get(addr, "/record/old"));
    timeout(Duration::from_secs(3), old_query_rx)
        .await
        .unwrap()
        .unwrap();
    let response = timeout(Duration::from_secs(3), first)
        .await
        .unwrap()
        .unwrap();
    assert!(
        response
            .to_ascii_lowercase()
            .contains("x-traffic-e2e-finite-response: 1")
    );
    let case_id = response
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-traffic-e2e-case-id")
                .then(|| value.trim().parse::<uuid::Uuid>().unwrap())
        })
        .expect("an early response must identify its still-owned case to the lease relay");
    assert!(state.inner.active_cases.has_case(case_id));
    if body_timeout {
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "headers already forwarded: {response}"
        );
        assert!(
            !response.ends_with("done"),
            "timed-out body must remain incomplete"
        );
    } else {
        assert!(response.starts_with("HTTP/1.1 504"), "{response}");
    }
    // No Source completion yet; a new case cannot be admitted.
    assert!(get(addr, "/record/new").await.ends_with("busy"));
    continue_tx.send(()).unwrap();
    timeout(Duration::from_secs(3), late_query_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(get(addr, "/record/new").await.ends_with("busy"));
    finish_tx.send(()).unwrap();
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await
    );
    assert!(
        timeout(Duration::from_secs(3), get(addr, "/record/new"))
            .await
            .unwrap()
            .ends_with("fresh")
    );
    source.await.unwrap();
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await
    );
    state.recorder().flush_traffic().await.unwrap();
    let run = state.recorder().run_dir.as_ref();
    let old = only_case(&run.join("failed/record-old"));
    let new = only_case(&run.join("apis/record-new"));
    let old_dependencies = std::fs::read_to_string(old.join("dependencies.jsonl")).unwrap();
    let new_dependencies = std::fs::read_to_string(new.join("dependencies.jsonl")).unwrap();
    assert!(old_dependencies.contains("old_before_timeout"));
    assert!(old_dependencies.contains("old_after_timeout"));
    assert!(!old_dependencies.contains("new_request"));
    assert!(new_dependencies.contains("new_request"));
    assert!(!new_dependencies.contains("old_before_timeout"));
    assert!(!new_dependencies.contains("old_after_timeout"));
    let report: Value =
        serde_json::from_slice(&std::fs::read(old.join("timeout-recovery.json")).unwrap()).unwrap();
    assert_eq!(report["phase"], "completed");
    assert_eq!(report["reset"]["connections_by_protocol"]["mysql"], 1);
    let error: Value =
        serde_json::from_slice(&std::fs::read(old.join("recording-error.json")).unwrap()).unwrap();
    assert_eq!(error["reason"], "upstream_response_error");
    server.abort();
}

#[tokio::test]
async fn failed_source_transport_after_timeout_stops_admission() {
    let temp = tempdir().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = AppState::new(config(temp.path(), upstream.local_addr().unwrap()))
        .await
        .unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let source = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        request(&mut stream).await;
        release_rx.await.unwrap();
        drop(stream);
    });
    let (addr, server) = gateway(state.clone()).await;
    assert!(
        timeout(Duration::from_secs(3), get(addr, "/record/old"))
            .await
            .unwrap()
            .starts_with("HTTP/1.1 504")
    );
    release_tx.send(()).unwrap();
    source.await.unwrap();
    assert!(
        state
            .inner
            .active_cases
            .wait_for_no_active_case(Duration::from_secs(3))
            .await
    );
    assert!(get(addr, "/record/new").await.ends_with("busy"));
    let case = only_case(&state.recorder().run_dir.join("failed/record-old"));
    let report: Value =
        serde_json::from_slice(&std::fs::read(case.join("timeout-recovery.json")).unwrap())
            .unwrap();
    assert_eq!(report["phase"], "source_completion_unconfirmed");
    server.abort();
}

fn only_case(group: &std::path::Path) -> std::path::PathBuf {
    let cases = std::fs::read_dir(group)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 1, "{}", group.display());
    cases[0].clone()
}
