use super::tests::{send_request, spawn_http_replay_with_policy, write_http_case};
use super::*;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

const HOST: &str = "erp.example.test";
const BODY: &str = "client_id=client&client_secret=private";

async fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
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

async fn finalized_report(runtime: &super::super::ReplayRuntime, path: &Path) {
    let mut state = runtime.state.lock().await;
    state.active_case_id = None;
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
    let plan = crate::plan_http_cross_case(crate::HttpCrossCaseFeedback {
        policy_path: path.clone(),
        case_source: consumer.clone(),
        replay_report_path: report,
        rule_id: "token".into(),
        selector: crate::HttpCrossCaseSelector {
            host: HOST.into(),
            port: 80,
            method: "POST".into(),
            path: "/token".into(),
        },
        source_evidence: "erp.py:ensure_token shared cache with expiry".into(),
    })
    .unwrap();
    assert!(plan.report().requires_replay);
    plan.apply().unwrap();
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
    runtime.state.lock().await.active_case_id = Some("consumer".into());
    assert_eq!(
        call(addr, "/token?audience=erp", BODY).await.status(),
        StatusCode::OK
    );
    assert_eq!(call(addr, "/membership", "").await.status(), StatusCode::OK);
    let mut state = runtime.state.lock().await;
    state.active_case_id = Some("origin".into());
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
    let (temp, origin, consumer) = fixture().await;
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
            host: HOST.into(),
            port: 80,
            method: "POST".into(),
            path: "/token".into(),
        },
        source_evidence: "erp.py:ensure_token shared cache".into(),
    };
    let plan = crate::plan_http_cross_case(feedback.clone()).unwrap();
    let file = origin.join("dependencies.jsonl");
    let original = fs::read_to_string(&file).unwrap();
    fs::write(&file, format!("{original}\n")).unwrap();
    assert!(plan.apply().is_err());
    assert!(
        !fs::read_to_string(&policy_path)
            .unwrap()
            .contains("recording_run")
    );
    let mut old: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    old["unmatched_http_requests"][0]
        .as_object_mut()
        .unwrap()
        .remove("request_fingerprint");
    fs::write(&report, old.to_string()).unwrap();
    let evidence = cross_case::discover(&consumer, &report, true).unwrap();
    assert_eq!(evidence["candidates"][0]["request_match"], "unavailable");
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
