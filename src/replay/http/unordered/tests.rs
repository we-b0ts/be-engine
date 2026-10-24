use super::super::tests::{send_request, spawn_http_replay_with_policy, write_http_case};
use super::*;
use crate::replay::policy::test_fixture::ManagedFixtureDirectory as TempDir;
use crate::{HttpUnorderedFeedback, plan_http_unordered};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

const HOST: &str = "erp.example.test";
const URI: &str = "/membership?scope=one&scope=two";
const SOURCE: &str = r#"{"ssn":"private-identity","department_ids":["B","A","A"],"ordered":[1,2]}"#;
const TARGET: &str = r#"{"ssn":"private-identity","department_ids":["A","B","A"],"ordered":[1,2]}"#;

async fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed","run_id":"one"}"#,
    )
    .unwrap();
    let case = temp.path().join("apis/models/case");
    write_http_case(&case, "fake_ip_http", HOST, URI, SOURCE, "recorded-members").await;
    fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/models"}"#,
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(&policy, "version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_rules: {json: {}}\n").unwrap();
    (temp, case, policy)
}

fn feedback(case: &Path, policy: &Path, report: &Path) -> HttpUnorderedFeedback {
    HttpUnorderedFeedback {
        policy_path: policy.into(),
        case_source: case.into(),
        replay_report_path: report.into(),
        rule_id: "erp-departments".into(),
        selector: HttpUnorderedSelector {
            host: HOST.into(),
            port: 80,
            method: "POST".into(),
            path: "/membership".into(),
            pointer: "/department_ids".into(),
        },
        source_evidence:
            "service.py:216 membership: department IDs come from a set and results are keyed by ID"
                .into(),
    }
}

async fn call(addr: SocketAddr, uri: &str, body: &str) -> Response<Incoming> {
    send_request(
        TokioIo::new(TcpStream::connect(addr).await.unwrap()),
        HOST,
        uri,
        body,
    )
    .await
}

async fn failure_report(case: &Path, output: &Path) {
    let (addr, runtime, task) = spawn_http_replay_with_policy(case, vec![], None, None).await;
    assert_eq!(
        call(addr, URI, TARGET).await.status(),
        StatusCode::BAD_GATEWAY
    );
    let mut state = runtime.state.lock().await;
    state.active_case_id = None;
    state.finalized_at = Some(Utc::now());
    fs::write(
        output,
        serde_json::to_vec(&state.snapshot_report()).unwrap(),
    )
    .unwrap();
    task.abort();
}

#[tokio::test]
async fn real_http_discovery_plan_apply_and_finite_replay() {
    let (temp, case, policy) = fixture().await;
    let report = temp.path().join("failed.json");
    failure_report(&case, &report).await;
    let evidence = evidence::discover(&report).unwrap();
    assert_eq!(evidence["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(
        evidence["candidates"][0]["selector"]["pointer"],
        "/department_ids"
    );
    assert_eq!(evidence["candidates"][0]["element_count"], 3);
    for secret in ["private-identity", "recorded-members", "scope=one"] {
        assert!(!evidence.to_string().contains(secret));
    }
    let error = plan_http_unordered(feedback(&case, &policy, &report))
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    crate::replay::policy::test_fixture::install_http_unordered(feedback(&case, &policy, &report))
        .unwrap();
    let text = fs::read_to_string(&policy).unwrap();
    assert!(text.contains("format: traffic-policy/v2"));
    assert!(!text.contains("query:"));
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    let response = call(addr, URI, TARGET).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "recorded-members"
    );
    let report = serde_json::to_value(runtime.state.lock().await.snapshot_report()).unwrap();
    let usage = &report["replay_policy"]["dependency_rules"][0];
    assert_eq!(usage["id"], "erp-departments");
    assert_eq!(usage["applicable"], true);
    assert_eq!(usage["matches"], 1);
    assert_eq!(usage["validations"], 1);
    assert_eq!(
        report["replay_policy"]["unused_applicable_dependency_rule_ids"],
        json!([])
    );
    assert_eq!(
        report["matched_http_exchanges"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        call(addr, URI, TARGET).await.status(),
        StatusCode::BAD_GATEWAY
    );
    task.abort();
}

#[tokio::test]
async fn unordered_keeps_query_presence_multiplicity_other_fields_and_array_contents_exact() {
    let (temp, case, policy) = fixture().await;
    let report = temp.path().join("failed.json");
    failure_report(&case, &report).await;
    crate::replay::policy::test_fixture::install_http_unordered(feedback(&case, &policy, &report))
        .unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec!["scope".into()], Some(policy), None).await;
    for (uri, body) in [
        ("/membership?scope=other&scope=two", TARGET.to_string()),
        ("/membership?scope=one", TARGET.to_string()),
        (
            "/membership?scope=one&scope=two&scope=two",
            TARGET.to_string(),
        ),
        (
            URI,
            TARGET.replace("private-identity", "different-identity"),
        ),
        (URI, TARGET.replace("[\"A\",\"B\",\"A\"]", "[\"A\",\"B\"]")),
        (
            URI,
            TARGET.replace("[\"A\",\"B\",\"A\"]", "[\"A\",\"B\",\"B\"]"),
        ),
        (
            URI,
            TARGET.replace("[\"A\",\"B\",\"A\"]", "[\"A\",\"B\",1]"),
        ),
        (URI, TARGET.replace("[1,2]", "[2,1]")),
        (URI, TARGET.replace("department_ids", "missing")),
    ] {
        assert_eq!(
            call(addr, uri, &body).await.status(),
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(runtime.state.lock().await.http_events.matched_count, 0);
    assert_eq!(
        call(addr, "/membership?scope=two&scope=one", TARGET)
            .await
            .status(),
        StatusCode::OK
    );
    task.abort();
}

#[tokio::test]
async fn stale_report_source_policy_and_missing_source_proof_cannot_apply() {
    let (temp, case, policy) = fixture().await;
    let report = temp.path().join("failed.json");
    failure_report(&case, &report).await;
    let mut no_proof = feedback(&case, &policy, &report);
    no_proof.source_evidence.clear();
    assert!(plan_http_unordered(no_proof).is_err());
    let original = fs::read(&policy).unwrap();
    let error = plan_http_unordered(feedback(&case, &policy, &report))
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(fs::read(&policy).unwrap(), original);
    fs::write(
        &report,
        r#"{"finalized":true,"unmatched_http_requests":[{}]}"#,
    )
    .unwrap();
    assert_eq!(
        evidence::discover(&report).unwrap()["requires_fresh_replay"],
        true
    );
    assert!(plan_http_unordered(feedback(&case, &policy, &report)).is_err());
}

#[test]
fn unordered_wildcards_preserve_nested_order_types_missing_values_and_duplicates() {
    let source = json!({"groups":[{"ids":["B","A","A"]}],"stable":1});
    let target = json!({"groups":[{"ids":["A","B","A"]}],"stable":1});
    assert!(normalize_arrays(
        &mut source.clone(),
        &mut target.clone(),
        "/groups/*/ids"
    ));
    for target in [
        json!({"groups":[{"ids":["A","B"]}],"stable":1}),
        json!({"groups":[{"ids":["A","B","B"]}],"stable":1}),
        json!({"groups":[{}],"stable":1}),
        json!({"groups":[{"ids":null}],"stable":1}),
        json!({"groups":[{"ids":["A","B",1]}],"stable":1}),
        json!({"groups":[{"ids":["A","B","A"]}],"stable":2}),
    ] {
        assert!(!normalize_arrays(
            &mut source.clone(),
            &mut target.clone(),
            "/groups/*/ids"
        ));
    }
    assert!(!normalize_arrays(
        &mut json!({"ids":[[1,2]]}),
        &mut json!({"ids":[[2,1]]}),
        "/ids"
    ));
}

#[test]
fn discovery_allows_separate_order_only_fields_without_treating_content_differences_as_order() {
    let source = json!({"a":[1,2],"b":[3,4],"nested":[[1,2]]});
    let target = json!({"a":[2,1],"b":[4,3],"nested":[[2,1]]});
    let mut paths = Vec::new();
    order_paths(&source, &target, "", &mut paths);
    assert_eq!(paths, ["/a", "/b", "/nested/0"]);
    let mut source = source;
    let mut target = target;
    assert!(!normalize_arrays(&mut source, &mut target, "/a"));
    assert!(!normalize_arrays(&mut source, &mut target, "/b"));
    assert!(normalize_arrays(&mut source, &mut target, "/nested/0"));
}

#[tokio::test]
async fn endpoint_and_schema_validation_reject_unreviewed_rule_expansion() {
    let (temp, case, policy) = fixture().await;
    let report = temp.path().join("failed.json");
    failure_report(&case, &report).await;
    for field in ["host", "port", "method", "path", "pointer"] {
        let mut request = feedback(&case, &policy, &report);
        match field {
            "host" => request.selector.host = "another.example.test".into(),
            "port" => request.selector.port = 81,
            "method" => request.selector.method = "PUT".into(),
            "path" => request.selector.path = "/another".into(),
            _ => request.selector.pointer = "/ordered".into(),
        }
        assert!(plan_http_unordered(request).is_err(), "{field}");
    }
    crate::replay::policy::test_fixture::install_http_unordered(feedback(&case, &policy, &report))
        .unwrap();
    let original = fs::read_to_string(&policy).unwrap();
    for invalid in [
        original.replace("traffic-policy/v2", "traffic-policy/v1"),
        original.replace("/department_ids:", "/bad~escape:"),
        original.replace("path: /membership", "path: /membership*"),
        original.replace(
            "path: /membership",
            "path: /membership\n    query: {nonce: {validate: uuid}}",
        ),
    ] {
        fs::write(&policy, invalid).unwrap();
        assert!(crate::validate_replay_policy(&policy).is_err());
    }
    let mut loaded: Value = serde_yaml::from_str(&original).unwrap();
    let mut duplicate = loaded["rules"][0].clone();
    duplicate["id"] = json!("overlapping-rule");
    loaded["rules"].as_array_mut().unwrap().push(duplicate);
    fs::write(&policy, serde_yaml::to_string(&loaded).unwrap()).unwrap();
    assert!(crate::validate_replay_policy(&policy).is_err());
}

#[tokio::test]
async fn a_rule_can_be_planned_for_one_path_while_another_unordered_path_still_blocks_replay() {
    let (temp, case, policy) = fixture().await;
    let report = temp.path().join("failed.json");
    let (addr, runtime, task) = spawn_http_replay_with_policy(&case, vec![], None, None).await;
    let target = TARGET.replace("[1,2]", "[2,1]");
    assert_eq!(
        call(addr, URI, &target).await.status(),
        StatusCode::BAD_GATEWAY
    );
    let mut state = runtime.state.lock().await;
    state.active_case_id = None;
    state.finalized_at = Some(Utc::now());
    fs::write(
        &report,
        serde_json::to_vec(&state.snapshot_report()).unwrap(),
    )
    .unwrap();
    drop(state);
    task.abort();
    let request = feedback(&case, &policy, &report);
    crate::replay::policy::test_fixture::install_http_unordered(request.clone()).unwrap();
    let (addr, _, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    assert_eq!(
        call(addr, URI, &target).await.status(),
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    let mut second = request;
    second.rule_id = "second-field".into();
    second.selector.pointer = "/ordered".into();
    crate::replay::policy::test_fixture::install_http_unordered(second).unwrap();
    let (addr, _, task) = spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    assert_eq!(call(addr, URI, &target).await.status(), StatusCode::OK);
    task.abort();
}
