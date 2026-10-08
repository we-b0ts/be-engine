//! Actual HTTP capture authoring and later path/query/body references retain strict fields.
use super::*;
use crate::{DynamicValueRuleFeedback, plan_dynamic_value_rule};
use serde_json::json;

#[tokio::test]
async fn http_capture_plan_apply_replay_keeps_static_json_and_pending_bindings_strict() {
    let temp = tempdir().unwrap();
    let case = temp.path().join("case");
    tokio::fs::create_dir(&case).await.unwrap();
    write_http_case(
        &case,
        "http",
        "api.example.test",
        "/create",
        r#"{"name":"source-name","stable":1}"#,
        "accepted",
    )
    .await;
    let later = case.join("later.jsonl");
    write_http_dependency(
        &later,
        "http",
        "api.example.test",
        "/items/source-name?name=source-name",
        r#"{"name":"source-name","stable":1}"#,
        "referenced",
    )
    .await;
    let dependencies = case.join("dependencies.jsonl");
    let mut bytes = tokio::fs::read(&dependencies).await.unwrap();
    bytes.extend_from_slice(&tokio::fs::read(later).await.unwrap());
    tokio::fs::write(&dependencies, &bytes).await.unwrap();
    tokio::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/items"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(case.join("expected-response.json"), "{}")
        .await
        .unwrap();
    let policy = temp.path().join("verification.yaml");
    tokio::fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .await
    .unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, Vec::new(), Some(policy.clone()), None).await;
    let response = send_request(
        TokioIo::new(TcpStream::connect(addr).await.unwrap()),
        "api.example.test",
        "/create",
        r#"{"name":"target-name","stable":1}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    drop(response);
    let report = temp.path().join("replay.json");
    {
        let mut state = runtime.state.lock().await;
        state.finalized_at = Some(chrono::Utc::now());
        let report_bytes = serde_json::to_vec(&state.snapshot_report()).unwrap();
        assert!(!String::from_utf8_lossy(&report_bytes).contains("target-name"));
        tokio::fs::write(&report, report_bytes).await.unwrap();
    }
    task.abort();
    let rule = serde_json::from_value(json!({"id":"name","api":"/items","targets":[{"host":"api.example.test","port":80}],"capture":{"protocol":"http","target":{"host":"api.example.test","port":80},"method":"POST","path":"/create","json_pointer":"/name"},"source_evidence":"Generator:create sends a fresh random name and reuses it in later requests"})).unwrap();
    plan_dynamic_value_rule(DynamicValueRuleFeedback {
        policy_path: policy.clone(),
        rule,
        replay_report: report,
    })
    .unwrap()
    .apply()
    .unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, Vec::new(), Some(policy), None).await;
    for (path, body, status) in [
        (
            "/create",
            r#"{"name":"target-name","stable":2}"#,
            StatusCode::BAD_GATEWAY,
        ),
        (
            "/items/target-name?name=target-name",
            r#"{"name":"target-name","stable":1}"#,
            StatusCode::BAD_GATEWAY,
        ),
        (
            "/create",
            r#"{"stable":1,"name":"target-name"}"#,
            StatusCode::OK,
        ),
        (
            "/items/target-name?name=target-name",
            r#"{"name":"wrong-name","stable":1}"#,
            StatusCode::BAD_GATEWAY,
        ),
        (
            "/items/target-name?name=target-name",
            r#"{"name":"target-name","stable":1}"#,
            StatusCode::OK,
        ),
        (
            "/create",
            r#"{"name":"target-name","stable":1}"#,
            StatusCode::BAD_GATEWAY,
        ),
    ] {
        let response = send_request(
            TokioIo::new(TcpStream::connect(addr).await.unwrap()),
            "api.example.test",
            path,
            body,
        )
        .await;
        assert_eq!(response.status(), status, "{path} {body}");
        response.into_body().collect().await.unwrap();
    }
    let state = runtime.state.lock().await;
    assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
    assert_eq!(
        state
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .dynamic_bindings
            .len(),
        1
    );
    assert_eq!(tokio::fs::read(dependencies).await.unwrap(), bytes);
    task.abort();
}
