use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::replay::policy::test_fixture::managed_tempdir as tempdir;
use hyper::client::conn::http1;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

use super::*;
use crate::replay::{MysqlReplayConfig, ReplayAllowedUnusedHttpConfig, ReplayRuntime};
#[path = "http_tests/dynamic_values.rs"]
mod dynamic_values;
#[path = "http_tests/http_body_jwt.rs"]
mod http_body_jwt;
#[path = "http_tests/json_request_time.rs"]
mod json_request_time;
#[path = "http_tests/multipart.rs"]
mod multipart;
#[path = "http_tests/request_contracts.rs"]
mod request_contracts;
#[path = "http_tests/server_termination.rs"]
mod server_termination;

#[test]
fn ignored_query_values_are_still_required_on_both_requests() {
    let ignored = vec!["signature".to_string()];
    assert!(
        uri_mismatch_reason(
            "/path?a=1&Signature=recorded",
            "/path?Signature=current&a=1",
            &ignored,
        )
        .is_none()
    );
    assert!(uri_mismatch_reason("/path?a=1&Signature=recorded", "/path?a=1", &ignored,).is_some());
}

#[test]
fn uri_mismatch_diagnostics_never_include_query_values() {
    let ignored = vec!["signature".to_string()];
    let reason = uri_mismatch_reason(
        "/path?a=recorded-secret&Signature=recorded-signature",
        "/path?a=current-secret&Signature=current-signature",
        &ignored,
    )
    .unwrap();
    assert_eq!(reason, "HTTP stable query parameter values differed for: a");
    assert!(!reason.contains("secret"));
    assert!(!reason.contains("signature"));

    let reason = uri_mismatch_reason(
        "/path?a=1&Signature=recorded-signature",
        "/path?b=1",
        &ignored,
    )
    .unwrap();
    assert_eq!(
        reason,
        "HTTP ignored query parameter presence differed: signature (recorded 1, actual 0)"
    );
    assert!(!reason.contains("recorded-signature"));
}

#[test]
fn one_fake_ip_is_reused_for_all_ports_on_a_host() {
    let mut targets = BTreeMap::new();
    for (port, protocol) in [(80, ReplayProtocol::Http), (443, ReplayProtocol::Https)] {
        let key = TargetKey {
            host: "same.example.test".to_string(),
            port,
        };
        register_replay_target(&mut targets, &key, protocol).unwrap();
    }
    let targets = super::super::assign_fake_ips(
        targets,
        super::super::Ipv4Cidr::parse("198.18.0.0/15").unwrap(),
    )
    .unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].fake_ip, targets[1].fake_ip);
}

#[test]
fn response_discovered_motan_target_reserves_its_recorded_fake_ip() {
    let record = RecordedHttpExchange {
        id: None,
        response_evidence: None,
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: None,
        request_started_at: None,
        request_headers: Default::default(),
        protected_request_headers: Default::default(),
        timestamp: None,
        scheme: "http".to_string(),
        method: "GET".to_string(),
        uri: "/naming/service?action=lookup&service=yf-rpc&cluster=user/service".to_string(),
        authority: Some("config.example.test".to_string()),
        request_body: RecordedBodyCapture {
            encoding: "utf8".to_string(),
            truncated: false,
            stored_len: Some(0),
            data: String::new(),
        },
        response_status: Some(200),
        response_headers: None,
        response_body: Some(RecordedBodyCapture {
            encoding: "utf8".to_string(),
            truncated: false,
            stored_len: Some(2),
            data: "{}".to_string(),
        }),
        response_stream: None,
        stream_delivery: None,
        materialized_proxy_failure: false,
        cleanup_authorized: false,
        lifecycle_stop: None,
        discovered_tcp_targets: vec![DiscoveredTcpTarget {
            protocol: "motan".to_string(),
            alias: "vintage-node-10-145-1-107.trp.test".to_string(),
            advertised_ip: "198.19.0.20".parse().unwrap(),
            upstream_ip: "10.145.1.107".parse().unwrap(),
            port: 8881,
            service: Some("yf-rpc".to_string()),
            cluster: Some("user/service".to_string()),
        }],
        capture: None,
        error: None,
    };
    let mut exchanges = Vec::new();
    let mut targets = BTreeMap::new();

    register_http_exchange(
        record,
        ReplaySource::Case,
        Some("case"),
        &mut exchanges,
        &mut targets,
    )
    .unwrap();

    let motan = targets
        .get(&TargetKey {
            host: "vintage-node-10-145-1-107.trp.test".to_string(),
            port: 8881,
        })
        .unwrap();
    assert_eq!(motan.protocol, ReplayProtocol::Motan);
    assert_eq!(motan.fake_ip, "198.19.0.20".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn response_discovered_http_target_reserves_its_recorded_fake_ip() {
    let record = RecordedHttpExchange {
        id: None,
        response_evidence: None,
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: None,
        request_started_at: None,
        request_headers: Default::default(),
        protected_request_headers: Default::default(),
        timestamp: None,
        scheme: "http".to_string(),
        method: "GET".to_string(),
        uri: "/naming/service?action=lookup&service=yf-rpc&cluster=user/service".to_string(),
        authority: Some("config.example.test".to_string()),
        request_body: RecordedBodyCapture {
            encoding: "utf8".to_string(),
            truncated: false,
            stored_len: Some(0),
            data: String::new(),
        },
        response_status: Some(200),
        response_headers: None,
        response_body: Some(RecordedBodyCapture {
            encoding: "utf8".to_string(),
            truncated: false,
            stored_len: Some(2),
            data: "{}".to_string(),
        }),
        response_stream: None,
        stream_delivery: None,
        materialized_proxy_failure: false,
        cleanup_authorized: false,
        lifecycle_stop: None,
        discovered_tcp_targets: vec![DiscoveredTcpTarget {
            protocol: "http".to_string(),
            alias: "http-10-145-1-107-8881.trp.test".to_string(),
            advertised_ip: "198.19.0.20".parse().unwrap(),
            upstream_ip: "10.145.1.107".parse().unwrap(),
            port: 8881,
            service: Some("yf-rpc".to_string()),
            cluster: Some("user/service".to_string()),
        }],
        capture: None,
        error: None,
    };
    let mut exchanges = Vec::new();
    let mut targets = BTreeMap::new();

    register_http_exchange(
        record,
        ReplaySource::Case,
        Some("case"),
        &mut exchanges,
        &mut targets,
    )
    .unwrap();

    let motan = targets
        .get(&TargetKey {
            host: "http-10-145-1-107-8881.trp.test".to_string(),
            port: 8881,
        })
        .unwrap();
    assert_eq!(motan.protocol, ReplayProtocol::Http);
    assert_eq!(motan.fake_ip, "198.19.0.20".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn tcp_blackhole_requires_case_local_clean_zero_byte_connection() {
    for (source, client_bytes, server_bytes, error, expected) in [
        (ReplaySource::Case, 0, 0, None, true),
        (ReplaySource::Case, 1, 0, None, false),
        (ReplaySource::Case, 0, 1, None, false),
        (
            ReplaySource::Case,
            0,
            0,
            Some("connect failed".to_string()),
            false,
        ),
        (ReplaySource::Startup, 0, 0, None, false),
    ] {
        let record = RecordedTcpGatewayConnection {
            domain: Some("api.example.test".to_string()),
            fake_addr: "198.19.0.1:80".to_string(),
            client_to_server_bytes: client_bytes,
            server_to_client_bytes: server_bytes,
            error,
        };
        let mut blackholes = Vec::new();
        let mut targets = BTreeMap::new();

        register_tcp_connection_blackhole(
            record,
            source,
            Some("case-a"),
            &mut blackholes,
            &mut targets,
        )
        .unwrap();

        assert_eq!(blackholes.len(), usize::from(expected));
        assert_eq!(targets.len(), usize::from(expected));
    }
}

#[tokio::test]
async fn replays_http_exchange_with_stable_query_matching() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-http");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        "/hello?b=2&Signature=recorded&a=1",
        "hello",
        "world",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, vec!["signature".to_string()]).await;

    let (providers, counts) = crate::protocols::tests::counted_providers();
    runtime.state.lock().await.providers = providers;
    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(
        TokioIo::new(stream),
        "api.example.test",
        "/hello?a=1&Signature=current&b=2",
        "hello",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "world"
    );

    let state = runtime.state.lock().await;
    assert_eq!(state.http_events.matched.len(), 1);
    assert!(state.http_events.unmatched.is_empty());
    assert!(
        state
            .unused_http_exchanges(ReplaySource::Case, false)
            .is_empty()
    );
    assert_eq!(
        counts
            .http
            .sessions
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        counts
            .http
            .native_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    task.abort();
}

#[tokio::test]
async fn replays_http_exchange_with_unscoped_dynamic_query_policy() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-http-policy");
    let recorded_uri = "/?Action=DescribeInstances&SignatureNonce=11111111111141118111111111111111&Timestamp=2026-07-15T04%3A30%3A00Z&Signature=old";
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        recorded_uri,
        "hello",
        "world",
    )
    .await;
    tokio::fs::write(
        case_dir.join("request.json"),
        r#"{"method":"GET","uri":"/api/aliyun/instance/attr","timestamp":"2026-07-15T04:30:00Z"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(case_dir.join("expected-response.json"), "{}")
        .await
        .unwrap();
    let policy_path = temp.path().join("replay.yaml");
    crate::replay::write_policy_fixture(
        &policy_path,
        r#"
version: 1
expected_response: assertions_only
dependency_rules:
  - id: aliyun-signature
    protocol: http
    target:
      host: api.example.test
      port: 80
    http:
      method: POST
      path: /
      query:
        Signature:
          validate: non_empty
        SignatureNonce:
          validate: uuid_v4
        Timestamp:
          time:
            relative_to: replay_now
            tolerance: 5s
"#,
    )
    .unwrap();
    let timestamp = Utc::now().format("%Y-%m-%dT%H%%3A%M%%3A%SZ");
    let actual_uri = format!(
        "/?Action=DescribeInstances&SignatureNonce=22222222222242228222222222222222&Timestamp={timestamp}&Signature=new"
    );
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case_dir, Vec::new(), Some(policy_path), None).await;
    runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .request_begin(case_dir.file_name().unwrap().to_str().unwrap())
        .unwrap();

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(
        TokioIo::new(stream),
        "api.example.test",
        &actual_uri,
        "hello",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let state = runtime.state.lock().await;
    let policy = state.snapshot_report().replay_policy.unwrap();
    assert!(policy.dependency_rules[0].applicable);
    assert_eq!(policy.dependency_rules[0].matches, 1);
    assert!(policy.unused_applicable_dependency_rule_ids.is_empty());
    task.abort();
}

#[tokio::test]
async fn replays_https_exchange_with_generated_mitm_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-https");
    write_http_case(
        &case_dir,
        "fake_ip_https",
        "secure.example.test",
        "/secure",
        "request",
        "secure-response",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let mut roots = RootCertStore::empty();
    roots.add(runtime.ca.ca_cert_der()).unwrap();
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let stream = TcpStream::connect(addr).await.unwrap();
    let tls = TlsConnector::from(client_config)
        .connect(
            ServerName::try_from("secure.example.test".to_string()).unwrap(),
            stream,
        )
        .await
        .unwrap();
    let response = send_request(
        TokioIo::new(tls),
        "secure.example.test",
        "/secure",
        "request",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "secure-response"
    );

    let state = runtime.state.lock().await;
    assert_eq!(state.http_events.matched.len(), 1);
    assert!(state.http_events.unmatched.is_empty());
    task.abort();
}

#[tokio::test]
async fn searches_past_same_target_global_exchange_for_active_case_match() {
    let temp = tempdir().unwrap();
    write_http_dependency(
        &temp.path().join("global-dependencies.jsonl"),
        "fake_ip_http",
        "api.example.test",
        "/bootstrap",
        "",
        "bootstrap-response",
    )
    .await;
    let case_dir = temp.path().join("case-http");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        "/case",
        "",
        "case-response",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/case", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "case-response"
    );

    let state = runtime.state.lock().await;
    assert_eq!(state.http_events.matched.len(), 1);
    assert_eq!(state.http_events.matched[0].source, ReplaySource::Case);
    assert!(state.http_events.unmatched.is_empty());
    assert_eq!(
        state
            .unused_http_exchanges(ReplaySource::Startup, false)
            .len(),
        1
    );
    assert!(
        state
            .unused_http_exchanges(ReplaySource::Case, false)
            .is_empty()
    );
    assert!(
        super::super::report_is_dirty(&state.snapshot_report()),
        "unobserved Startup business inventory remains formal batch debt"
    );
    assert_eq!(state.startup_phase.report().status, "phase_unverified");
    task.abort();
}

#[tokio::test]
async fn preflight_probe_global_exchange_is_repeatable_for_system_and_target_checks() {
    let temp = tempdir().unwrap();
    let mut dependency = serde_json::json!({
        "event_type": "http_exchange",
        "id": uuid::Uuid::new_v4(),
        "scheme": "fake_ip_http",
        "method": "POST",
        "uri": "/probe",
        "authority": "api.example.test",
        "request_body": body_capture(""),
        "response_status": 200,
        "response_headers": {"content-type": ["text/plain"], "content-length": ["2"]},
        "response_body": body_capture("ok"),
        "global_dependency_reason": "preflight_probe",
        "global_dependency_phase": "runtime",
        "global_dependency_matched_by": "system_network",
        "error": null
    });
    let mut capture = crate::dependency::observation::fixture_capture("startup");
    capture.attribution = crate::dependency::attribution::DependencyOwner::Startup {
        process_epoch: capture.process_epoch,
        initialization_unit: "preflight_probe/system_network".into(),
    };
    dependency["capture"] = serde_json::to_value(capture).unwrap();
    tokio::fs::write(
        temp.path().join("global-dependencies.jsonl"),
        format!("{}\n", serde_json::to_string(&dependency).unwrap()),
    )
    .await
    .unwrap();
    let case_dir = temp.path().join("case-http");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        "/case",
        "",
        "case",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    for _ in 0..2 {
        let stream = TcpStream::connect(addr).await.unwrap();
        let response = send_request(TokioIo::new(stream), "api.example.test", "/probe", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let state = runtime.state.lock().await;
    assert_eq!(state.http_events.matched.len(), 2);
    assert!(state.http_events.unmatched.is_empty());
    assert!(
        state
            .unused_http_exchanges(ReplaySource::Startup, false)
            .is_empty()
    );
    task.abort();
}

#[tokio::test]
async fn unmatched_http_request_is_dirty_and_does_not_consume_exchange() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-unmatched");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        "/expected",
        "",
        "ok",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/different", "").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert_eq!(report.unused_case_http_exchanges.len(), 1);
    assert!(super::super::report_is_dirty(&report));
    task.abort();
}

#[tokio::test]
async fn unmatched_http_outside_a_case_is_reference_context_not_dirty() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-unscoped");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "api.example.test",
        "/expected",
        "",
        "ok",
    )
    .await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/expected", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    runtime.state.lock().await.set_active_case(None);

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/warmup", "").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert!(report.unmatched_http_requests[0].case_id.is_none());
    assert!(report.unused_case_http_exchanges.is_empty());
    assert!(!super::super::report_is_dirty(&report));
    task.abort();
}

#[tokio::test]
async fn allowed_unused_http_host_is_diagnostic_but_unmatched_requests_stay_dirty() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-allowed-unused");
    write_http_case(
        &case_dir,
        "fake_ip_http",
        "background.example.test",
        "/periodic/one",
        "",
        "ok",
    )
    .await;
    let allowed = ReplayAllowedUnusedHttpConfig {
        config_path: temp.path().join("project.yaml"),
        hosts: BTreeSet::from(["background.example.test".to_string()]),
    };
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case_dir, Vec::new(), None, Some(allowed)).await;

    {
        let state = runtime.state.lock().await;
        let report = state.snapshot_report();
        assert!(report.unused_case_http_exchanges.is_empty());
        assert_eq!(report.allowed_unused_case_http_exchanges.len(), 1);
        assert!(!super::super::report_is_dirty(&report));
        let config = report.allowed_unused_http.unwrap();
        assert_eq!(config.hosts, vec!["background.example.test"]);
    }

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(
        TokioIo::new(stream),
        "background.example.test",
        "/periodic/two",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let state = runtime.state.lock().await;
    let report = state.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert!(super::super::report_is_dirty(&report));
    task.abort();
}

#[tokio::test]
async fn auto_http_target_without_a_blackhole_returns_bad_gateway() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-auto-http");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    tokio::fs::write(
        case_dir.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        r#"{"version":1,"resolved_domains":["api.example.test"],"accessed_endpoints":[{"host":"api.example.test","port":80}]}"#,
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/missing", "").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let report = runtime.state.lock().await.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert!(super::super::report_is_dirty(&report));

    task.abort();
}

#[tokio::test]
async fn case_zero_byte_tcp_connection_blackholes_one_http_request_without_evidence() {
    let temp = tempdir().unwrap();
    let case_dir = temp.path().join("case-blackhole");
    write_tcp_gateway_connection(&case_dir, "api.example.test", 80).await;
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let client = assert_http_request_hangs(addr, "api.example.test", "/timeout").await;
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.unmatched_http_requests.is_empty());
    assert!(!super::super::report_is_dirty(&report));
    drop(client);

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/timeout", "").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let report = runtime.state.lock().await.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert!(super::super::report_is_dirty(&report));

    task.abort();
}

#[tokio::test]
async fn global_zero_byte_tcp_connection_does_not_blackhole_a_case_request() {
    let temp = tempdir().unwrap();
    write_tcp_gateway_dependency(
        &temp.path().join("global-dependencies.jsonl"),
        "api.example.test",
        80,
    )
    .await;
    let case_dir = temp.path().join("case-global-blackhole");
    tokio::fs::create_dir_all(&case_dir).await.unwrap();
    tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
        .await
        .unwrap();
    tokio::fs::write(
        case_dir.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
        r#"{"version":1,"resolved_domains":["api.example.test"],"accessed_endpoints":[{"host":"api.example.test","port":80}]}"#,
    )
    .await
    .unwrap();
    let (addr, runtime, task) = spawn_http_replay(&case_dir, Vec::new()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let response = send_request(TokioIo::new(stream), "api.example.test", "/timeout", "").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let report = runtime.state.lock().await.snapshot_report();
    assert_eq!(report.unmatched_http_requests.len(), 1);
    assert!(super::super::report_is_dirty(&report));

    task.abort();
}

pub(super) async fn spawn_http_replay(
    case_dir: &Path,
    ignored_query_params: Vec<String>,
) -> (
    std::net::SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    spawn_http_replay_with_policy(case_dir, ignored_query_params, None, None).await
}

pub(super) async fn spawn_http_replay_with_policy(
    case_dir: &Path,
    ignored_query_params: Vec<String>,
    policy_path: Option<PathBuf>,
    allowed_unused_http: Option<ReplayAllowedUnusedHttpConfig>,
) -> (
    std::net::SocketAddr,
    Arc<ReplayRuntime>,
    tokio::task::JoinHandle<()>,
) {
    super::super::write_test_recording_network_manifest(case_dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case_dir.to_path_buf(),
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: Some(case_dir.join(".replay/report.json")),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(case_dir.join(".replay/ca.pem")),
                ca_key_path: Some(case_dir.join(".replay/ca-key.pem")),
                policy_path,
                http_ignore_query_params: ignored_query_params,
                process_owned_dependencies: Vec::new(),
                allowed_unused_http,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap(),
    );
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = task_runtime.run_tcp(listener) => {},
            _ = task_runtime.run_report_writer() => {},
        }
    });
    (addr, runtime, task)
}

pub(super) async fn send_request<T>(
    io: TokioIo<T>,
    host: &str,
    uri: &str,
    body: &str,
) -> Response<Incoming>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(HOST, host)
                .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn assert_http_request_hangs(addr: std::net::SocketAddr, host: &str, uri: &str) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {uri} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = [0_u8; 1];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(150),
            client.read(&mut response),
        )
        .await
        .is_err(),
        "unmatched HTTP dependency must neither respond nor close"
    );
    client
}

pub(crate) async fn write_http_case(
    case_dir: &Path,
    scheme: &str,
    authority: &str,
    uri: &str,
    request_body: &str,
    response_body: &str,
) {
    tokio::fs::create_dir_all(case_dir).await.unwrap();
    write_http_dependency(
        &case_dir.join("dependencies.jsonl"),
        scheme,
        authority,
        uri,
        request_body,
        response_body,
    )
    .await;
}

async fn write_tcp_gateway_connection(case_dir: &Path, domain: &str, port: u16) {
    tokio::fs::create_dir_all(case_dir).await.unwrap();
    write_tcp_gateway_dependency(&case_dir.join("dependencies.jsonl"), domain, port).await;
}

async fn write_tcp_gateway_dependency(path: &Path, domain: &str, port: u16) {
    let dependency = serde_json::json!({
        "event_type": "tcp_gateway_connection",
        "domain": domain,
        "fake_addr": format!("198.19.0.1:{port}"),
        "client_to_server_bytes": 0,
        "server_to_client_bytes": 0,
        "duration_ms": 103,
        "error": null
    });
    tokio::fs::write(
        path,
        format!("{}\n", serde_json::to_string(&dependency).unwrap()),
    )
    .await
    .unwrap();
}

pub(super) async fn write_http_dependency(
    path: &Path,
    scheme: &str,
    authority: &str,
    uri: &str,
    request_body: &str,
    response_body: &str,
) {
    let dependency = serde_json::json!({
        "event_type": "http_exchange",
        "request_started_at": "2026-07-15T04:30:00Z",
        "timestamp": "2026-07-15T04:30:00Z",
        "duration_ms": 0,
        "scheme": scheme,
        "id": uuid::Uuid::new_v4(),
        "method": "POST",
        "uri": uri,
        "authority": authority,
        "request_body": body_capture(request_body),
        "response_status": 200,
        "response_headers": {"content-type": ["text/plain"], "content-length": [response_body.len().to_string()]},
        "response_body": body_capture(response_body),
        "error": null
    });
    tokio::fs::write(
        path,
        format!("{}\n", serde_json::to_string(&dependency).unwrap()),
    )
    .await
    .unwrap();
}

fn body_capture(value: &str) -> Value {
    serde_json::json!({
        "encoding": "base64",
        "original_len": value.len(),
        "stored_len": value.len(),
        "truncated": false,
        "data": STANDARD.encode(value.as_bytes())
    })
}

/// Opaque test adapter keeps Replay's internal runtime inside its owner.
pub(crate) struct TestHttpReplayRuntime(Arc<ReplayRuntime>);

pub(crate) async fn spawn_coordinator_http_replay(
    case: &Path,
    policy: Option<PathBuf>,
) -> (
    std::net::SocketAddr,
    TestHttpReplayRuntime,
    tokio::task::JoinHandle<()>,
) {
    let (addr, runtime, task) = spawn_http_replay_with_policy(case, vec![], policy, None).await;
    (addr, TestHttpReplayRuntime(runtime), task)
}

pub(crate) async fn snapshot_http_replay(runtime: &TestHttpReplayRuntime) -> Value {
    serde_json::to_value(runtime.0.state.lock().await.snapshot_report()).unwrap()
}
