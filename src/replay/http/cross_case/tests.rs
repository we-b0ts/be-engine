use super::tests::{send_request, spawn_http_replay_with_policy, write_http_case};
use super::*;
use crate::HttpCrossCaseSelector;
use crate::replay::policy::test_fixture::ManagedFixtureDirectory as TempDir;
use hyper::client::conn::http1;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

const HOST: &str = "erp.example.test";
const BODY: &str = "client_id=client&client_secret=private";

#[tokio::test]
async fn sharing_proof_checks_records_beyond_the_bounded_candidate_preview() {
    let (temp, origin, consumer) = fixture().await;
    let path = origin.join("dependencies.jsonl");
    let line = fs::read_to_string(&path).unwrap();
    let record: serde_json::Value = serde_json::from_str(
        line.lines()
            .find(|line| line.contains("http_exchange"))
            .unwrap(),
    )
    .unwrap();
    fs::write(
        &path,
        (0..65)
            .map(|_| record.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let (addr, runtime, task) = spawn_http_replay_with_policy(&consumer, vec![], None, None).await;
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    let report = temp.path().join("proof.json");
    finalized_report(&runtime, &report).await;
    task.abort();
    let selector = HttpCrossCaseSelector {
        host: Some(HOST.into()),
        port: Some(80),
        method: "POST".into(),
        path: "/token".into(),
    };
    let verified = cross_case::verify_candidate(&consumer, &report, &selector).unwrap();
    assert_eq!(verified["matching_exchanges"], 65);
    assert_eq!(verified["complete"], true);
    let global = HttpCrossCaseSelector {
        host: None,
        port: None,
        ..selector.clone()
    };
    assert_eq!(
        cross_case::verify_candidate(&consumer, &report, &global).unwrap()["matching_exchanges"],
        65
    );
    let mut invalid = record.clone();
    invalid["response_body"]["truncated"] = json!(true);
    fs::write(
        path,
        (0..65)
            .map(|index| {
                if index == 64 {
                    invalid.to_string()
                } else {
                    record.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    assert!(cross_case::verify_candidate(&consumer, &report, &selector).is_err());
}

async fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed","run_id":"one"}"#,
    )
    .unwrap();
    let origin = temp.path().join("apis/download/origin");
    let consumer = temp.path().join("apis/models/consumer");
    write_http_case(
        &origin,
        "fake_ip_http",
        HOST,
        "/token?audience=erp",
        BODY,
        "token-response",
    )
    .await;
    write_http_case(
        &consumer,
        "fake_ip_http",
        HOST,
        "/membership",
        "",
        "members",
    )
    .await;
    for (case, api) in [(&origin, "/download"), (&consumer, "/models")] {
        fs::write(
            case.join("request.json"),
            json!({"method":"GET", "uri":api}).to_string(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();
    }
    (temp, origin, consumer)
}

fn policy(root: &Path) -> PathBuf {
    let path = root.join("policy.yaml");
    crate::replay::write_policy_fixture(&path, format!("version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: token\n  protocol: http\n  target: {{host: {HOST}, port: 80}}\n  http: {{method: POST, path: /token}}\n  replay_scope: recording_run\n  source_evidence: 'erp.py:ensure_token caches a shared token with expiry'\n")).unwrap();
    path
}

async fn call(addr: std::net::SocketAddr, path: &str, body: &str) -> Response<Incoming> {
    send_request(
        TokioIo::new(TcpStream::connect(addr).await.unwrap()),
        HOST,
        path,
        body,
    )
    .await
}

fn install_run_network_manifest(root: &Path, consumer: &Path) {
    // The real Recorder publishes one endpoint inventory for the full run.
    // Derive that inventory from these Source fixtures before the HTTP helper
    // supplies its default consumer-only inventory.
    super::super::write_test_recording_network_manifest(root);
    let name = crate::recording_network::RECORDING_NETWORK_FILENAME;
    fs::copy(root.join(name), consumer.join(name)).unwrap();
}

/// A gateway socket already belongs to one physical destination. Exercise a
/// different recorded destination through its own real TCP transport, rather
/// than trying to change that destination by changing the HTTP Host header.
async fn call_source_target(
    runtime: &Arc<super::super::ReplayRuntime>,
    host: &str,
    port: u16,
    path: &str,
    body: &str,
) -> Response<Incoming> {
    let stream = source_target_stream(runtime, host, port).await;
    let authority = if port == 80 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    send_request(TokioIo::new(stream), &authority, path, body).await
}

async fn source_target_stream(
    runtime: &Arc<super::super::ReplayRuntime>,
    host: &str,
    port: u16,
) -> TcpStream {
    let mut target = runtime
        .state
        .lock()
        .await
        .targets
        .iter()
        .find(|target| target.host == host && target.port == port)
        .expect("recorded physical HTTP target")
        .clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (server, peer) = server.unwrap();
    let state = runtime.state.clone();
    let ca = runtime.ca.clone();
    tokio::spawn(async move {
        if target.protocol == ReplayProtocol::Auto {
            target.protocol = super::super::auto_protocol::detect(&server)
                .await
                .unwrap()
                .expect("Target sends a detectable HTTP request");
        }
        super::handle_http_replay_connection(server, peer, target, state, ca)
            .await
            .unwrap();
    });
    client.unwrap()
}

async fn finalized_report(runtime: &super::super::ReplayRuntime, path: &Path) {
    let mut state = runtime.state.lock().await;
    state.set_active_case(None);
    state.finalized_at = Some(Utc::now());
    fs::write(path, serde_json::to_vec(&state.snapshot_report()).unwrap()).unwrap();
}

#[tokio::test]
async fn unmatched_discovers_other_api_without_serving_it_and_plan_apply_enables_replay() {
    let (temp, _, consumer) = fixture().await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&consumer, vec![], None, None).await;
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    let report = temp.path().join("failed-replay.json");
    finalized_report(&runtime, &report).await;
    let evidence = cross_case::discover(&consumer, &report, true).unwrap();
    assert_eq!(evidence["candidates"][0]["origin_case_id"], "origin");
    assert_eq!(evidence["candidates"][0]["request_match"], "verified");
    assert!(!evidence.to_string().contains("private"));
    assert!(!evidence.to_string().contains("token-response"));
    assert_eq!(
        evidence,
        cross_case::discover(&consumer, &report, true).unwrap()
    );
    task.abort();

    let path = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
        &path,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    crate::replay::policy::test_fixture::install_http_cross_case(crate::HttpCrossCaseFeedback {
        policy_path: path.clone(),
        case_source: consumer.clone(),
        replay_report_path: report,
        rule_id: "token".into(),
        selector: crate::HttpCrossCaseSelector {
            host: Some(HOST.into()),
            port: Some(80),
            method: "POST".into(),
            path: "/token".into(),
        },
        source_evidence: "erp.py:ensure_token shared cache with expiry".into(),
    })
    .unwrap();
    assert!(!fs::read_to_string(&path).unwrap().contains("query:"));
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&consumer, vec![], Some(path), None).await;
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::OK
    );
    assert_eq!(call(addr, "/membership", "").await.status(), StatusCode::OK);
    let state = runtime.state.lock().await;
    let result = state.snapshot_report();
    assert!(!super::super::report_is_dirty(&result));
    let value = serde_json::to_value(&result).unwrap();
    assert_eq!(value["matched_http_exchanges"][0]["case_id"], "consumer");
    assert_eq!(
        value["matched_http_exchanges"][0]["shared_origin"]["case_id"],
        "origin"
    );
    drop(state);
    // Each exchange is finite; a second target fetch stays dirty.
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    task.abort();
}

#[tokio::test]
async fn resource_free_http_sharing_keeps_endpoint_headers_and_finite_consumption_strict() {
    let (temp, _, consumer) = fixture().await;
    let other = temp.path().join("apis/download/other-origin");
    write_http_case(
        &other,
        "fake_ip_http",
        "other.example.test",
        "/token?audience=erp",
        BODY,
        "other-response",
    )
    .await;
    fs::write(
        other.join("request.json"),
        json!({"method":"GET","uri":"/other"}).to_string(),
    )
    .unwrap();
    fs::write(other.join("expected-response.json"), "{}").unwrap();
    install_run_network_manifest(temp.path(), &consumer);
    let path = temp.path().join("global-sharing.yaml");
    fs::write(
        &path,
        r#"format: traffic-policy/v3
rules:
- id: shared-token
  match: {operation: POST, path: /token}
  effect: {kind: finite_sharing, protocol: http}
"#,
    )
    .unwrap();
    let (_addr, runtime, task) =
        spawn_http_replay_with_policy(&consumer, vec![], Some(path), None).await;
    let (mut sender, connection) =
        http1::handshake(TokioIo::new(source_target_stream(&runtime, HOST, 80).await))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let with_extra_credentials = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/token?audience=erp")
                .header(hyper::header::HOST, HOST)
                .header(hyper::header::AUTHORIZATION, "Bearer unexpected")
                .body(Full::new(Bytes::from_static(BODY.as_bytes())))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        with_extra_credentials.status(),
        StatusCode::BAD_GATEWAY,
        "a missing Source credential is an exact absence, not an optional identity header"
    );
    assert_eq!(runtime.state.lock().await.http_events.matched_count, 0);
    assert_eq!(
        call_source_target(&runtime, HOST, 80, "/token?audience=erp", BODY)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        call_source_target(&runtime, HOST, 80, "/token?audience=erp", BODY)
            .await
            .status(),
        StatusCode::BAD_GATEWAY,
        "the same request on another Source endpoint cannot replace an exhausted local entry"
    );
    let other = call_source_target(
        &runtime,
        "other.example.test",
        80,
        "/token?audience=erp",
        BODY,
    )
    .await;
    assert_eq!(other.status(), StatusCode::OK);
    assert_eq!(runtime.state.lock().await.http_events.matched_count, 2);
    task.abort();
}

#[tokio::test]
async fn a_host_only_http_cache_uses_source_ports_and_excludes_other_hosts() {
    let (temp, _, consumer) = fixture().await;
    for (case, authority) in [
        ("another-port", format!("{HOST}:8080")),
        ("foreign-host", "foreign.example.test".into()),
    ] {
        let origin = temp.path().join("apis/cache").join(case);
        write_http_case(
            &origin,
            "fake_ip_http",
            &authority,
            "/token?audience=erp",
            BODY,
            "token",
        )
        .await;
        fs::write(
            origin.join("request.json"),
            json!({"method":"GET","uri":format!("/{case}")}).to_string(),
        )
        .unwrap();
        fs::write(origin.join("expected-response.json"), "{}").unwrap();
    }
    install_run_network_manifest(temp.path(), &consumer);
    let path = temp.path().join("host-cache.yaml");
    fs::write(&path,format!("format: traffic-policy/v3\nrules:\n- id: host-token\n  match: {{host: {HOST}, operation: POST, path: /token}}\n  effect: {{kind: finite_sharing, protocol: http}}\n")).unwrap();
    let (_addr, runtime, task) =
        spawn_http_replay_with_policy(&consumer, vec![], Some(path), None).await;
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .http_exchanges
            .iter()
            .filter(|exchange| exchange.shared_origin.is_some())
            .count(),
        2
    );
    for port in [80, 8080] {
        let response = call_source_target(&runtime, HOST, port, "/token?audience=erp", BODY).await;
        assert_eq!(response.status(), StatusCode::OK, "{HOST}:{port}");
    }
    let foreign = call_source_target(
        &runtime,
        "foreign.example.test",
        80,
        "/token?audience=erp",
        BODY,
    )
    .await;
    assert_eq!(foreign.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        call_source_target(&runtime, HOST, 80, "/token?audience=erp", BODY)
            .await
            .status(),
        StatusCode::BAD_GATEWAY
    );
    task.abort();
}

#[tokio::test]
async fn lazy_shared_http_skip_lines_are_selected_from_real_source_ports() {
    let (_temp, origin, _) = fixture().await;
    let path = origin.join("dependencies.jsonl");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let mut other_port = original.clone();
    other_port["id"] = json!(uuid::Uuid::new_v4());
    other_port["authority"] = json!(format!("{HOST}:8080"));
    let mut foreign = original.clone();
    foreign["id"] = json!(uuid::Uuid::new_v4());
    foreign["authority"] = json!("foreign.example.test");
    fs::write(&path, format!("{original}\n{other_port}\n{foreign}\n")).unwrap();
    let index = crate::dependency_index::load_file(&path).unwrap();
    let mut reader = crate::dependency_index::RecordReader::new(1024 * 1024);
    let selector = HttpCrossCaseSelector {
        host: Some(HOST.into()),
        port: None,
        method: "POST".into(),
        path: "/token".into(),
    };
    assert_eq!(
        cross_case::selected_source_lines(
            &path,
            &index,
            &mut reader,
            std::slice::from_ref(&selector)
        )
        .unwrap(),
        BTreeSet::from([1, 2])
    );
    assert_eq!(
        cross_case::selected_source_lines(
            &path,
            &index,
            &mut reader,
            &[HttpCrossCaseSelector {
                port: Some(8080),
                ..selector
            }]
        )
        .unwrap(),
        BTreeSet::from([2])
    );
}

#[tokio::test]
async fn scope_keeps_query_body_and_identity_headers_exact_despite_global_ignores() {
    let (temp, _, consumer) = fixture().await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(
        &consumer,
        vec!["audience".into()],
        Some(policy(temp.path())),
        None,
    )
    .await;
    for (path, body) in [
        ("/token?audience=other", BODY),
        ("/token", BODY),
        ("/token?audience=erp&audience=erp", BODY),
        (
            "/token?audience=erp",
            "client_id=other&client_secret=private",
        ),
    ] {
        assert_eq!(
            call(addr, path, body).await.status(),
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::OK
    );
    assert_eq!(runtime.state.lock().await.http_events.matched_count, 1);
    task.abort();
}

#[tokio::test]
async fn full_run_loads_shared_exchange_once_and_original_case_does_not_require_it_again() {
    let (temp, _, _) = fixture().await;
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(temp.path(), vec![], Some(policy(temp.path())), None).await;
    runtime
        .state
        .lock()
        .await
        .set_active_case(Some("consumer".into()));
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::OK
    );
    assert_eq!(call(addr, "/membership", "").await.status(), StatusCode::OK);
    let mut state = runtime.state.lock().await;
    state.set_active_case(Some("origin".into()));
    assert!(
        state
            .unused_http_exchanges(ReplaySource::Case, false)
            .is_empty()
    );
    assert_eq!(
        state
            .http_exchanges
            .iter()
            .filter(|e| e.shared_origin.is_some())
            .count(),
        1
    );
    assert!(!super::super::report_is_dirty(&state.snapshot_report()));
    task.abort();
}

#[test]
fn identity_normalizes_query_order_and_json_object_order_but_preserves_values() {
    let headers = HeaderSnapshot::new();
    let first = cross_case::request_fingerprint("/x?a=1&b=2", br#"{"a":1,"b":[2,3]}"#, &headers);
    assert_eq!(
        first,
        cross_case::request_fingerprint("/x?b=2&a=1", br#"{"b":[2,3],"a":1}"#, &headers)
    );
    assert_ne!(
        first,
        cross_case::request_fingerprint("/x?a=1&b=2", br#"{"a":1,"b":[3,2]}"#, &headers)
    );
    let auth = BTreeMap::from([("Authorization".into(), vec!["Bearer private".into()])]);
    assert_ne!(
        first,
        cross_case::request_fingerprint("/x?a=1&b=2", br#"{"a":1,"b":[2,3]}"#, &auth)
    );
}

#[tokio::test]
async fn different_query_or_body_never_produces_a_verified_candidate() {
    let (temp, _, consumer) = fixture().await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&consumer, vec![], None, None).await;
    assert_eq!(
        call(addr, "/token?audience=wrong", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        call(addr, "/token?audience=erp", "client_id=different")
            .await
            .status(),
        StatusCode::BAD_GATEWAY
    );
    let report = temp.path().join("failed.json");
    finalized_report(&runtime, &report).await;
    let evidence = cross_case::discover(&consumer, &report, true).unwrap();
    assert!(evidence["candidates"].as_array().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn old_report_only_hints_and_changed_evidence_rejects_apply() {
    let (temp, _origin, consumer) = fixture().await;
    let (addr, runtime, task) = spawn_http_replay_with_policy(&consumer, vec![], None, None).await;
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    let report = temp.path().join("failed.json");
    finalized_report(&runtime, &report).await;
    let policy_path = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
        &policy_path,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let feedback = crate::HttpCrossCaseFeedback {
        policy_path: policy_path.clone(),
        case_source: consumer.clone(),
        replay_report_path: report.clone(),
        rule_id: "token".into(),
        selector: crate::HttpCrossCaseSelector {
            host: Some(HOST.into()),
            port: Some(80),
            method: "POST".into(),
            path: "/token".into(),
        },
        source_evidence: "erp.py:ensure_token shared cache".into(),
    };
    let error = crate::plan_http_cross_case(feedback.clone()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert!(
        !fs::read_to_string(&policy_path)
            .unwrap()
            .contains("finite_sharing")
    );
    let mut old: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    old["unmatched_http_requests"][0]
        .as_object_mut()
        .unwrap()
        .remove("request_fingerprint");
    fs::write(&report, old.to_string()).unwrap();
    let evidence = cross_case::discover(&consumer, &report, true).unwrap();
    assert_eq!(evidence["candidates"][0]["request_match"], "unavailable");
    assert!(
        cross_case::verify_candidate(
            &consumer,
            &report,
            &HttpCrossCaseSelector {
                host: None,
                port: None,
                ..feedback.selector.clone()
            }
        )
        .is_err(),
        "an unscoped declaration still needs exact Target request evidence"
    );
    assert!(crate::plan_http_cross_case(feedback).is_err());
    task.abort();
}

#[tokio::test]
async fn shared_rule_rejects_truncated_evidence_and_scope_cannot_escape_its_run() {
    let (temp, origin, consumer) = fixture().await;
    let nested = temp.path().join("other-run");
    fs::create_dir_all(&nested).unwrap();
    fs::write(
        nested.join("recording-run.json"),
        r#"{"status":"completed","run_id":"two"}"#,
    )
    .unwrap();
    write_http_case(
        &nested.join("foreign"),
        "fake_ip_http",
        HOST,
        "/token?audience=erp",
        BODY,
        "foreign",
    )
    .await;
    let path = policy(temp.path());
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&consumer, vec![], Some(path.clone()), None).await;
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .http_exchanges
            .iter()
            .filter(|e| e.shared_origin.is_some())
            .count(),
        1
    );
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    let file = origin.join("dependencies.jsonl");
    let mut record: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    record["response_body"]["truncated"] = json!(true);
    fs::write(&file, record.to_string()).unwrap();
    let state = runtime.state.lock().await;
    assert!(
        cross_case::load(
            &consumer,
            Some(&path),
            &state.cases,
            &mut vec![],
            &mut BTreeMap::new()
        )
        .is_err()
    );
}
