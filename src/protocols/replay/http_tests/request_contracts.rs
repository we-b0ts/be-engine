//! Native multipart rules retain their evidence and finite-delivery accounting.
use super::*;
use crate::{DependencyRequestRuleFeedback, plan_dependency_request_rule};
use serde_json::json;

fn multipart(boundary: &str, value: &str) -> String {
    format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n{value}\r\n--{boundary}--\r\n"
    )
}
async fn send(addr: SocketAddr, body: String, authorization: &str) -> StatusCode {
    let (mut sender, connection) =
        http1::handshake(TokioIo::new(TcpStream::connect(addr).await.unwrap()))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("/upload?mode=original")
                .header("host", "api.example.test")
                .header(
                    "content-type",
                    "multipart/form-data; boundary=target-boundary",
                )
                .header("authorization", authorization)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    status
}
#[tokio::test]
async fn multipart_default_and_native_rule_keep_finite_delivery_and_protected_evidence() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let contents = format!("private-file-bytes{}", "x".repeat(1024 * 1024));
    let file = contents.as_str();
    let local = root.join(".traffic-e2e/local");
    let key = std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV)
        .unwrap_or_else(|_| STANDARD.encode([7u8; 32]));
    let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    std::fs::write(key_path, key).unwrap();
    let case = local.join("recordings/run/case");
    write_http_case(
        &case,
        "http",
        "api.example.test",
        "/upload?mode=original",
        &multipart("source", file),
        "accepted",
    )
    .await;
    let dependencies = case.join("dependencies.jsonl");
    let mut source: Value = serde_json::from_slice(&std::fs::read(&dependencies).unwrap()).unwrap();
    source["request_headers"] = json!({"content-type":["multipart/form-data; boundary=source"],"authorization":["Bearer secret"]});
    std::fs::write(&dependencies, format!("{source}\n")).unwrap();
    let original = std::fs::read(&dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/attachments/1","timestamp":"2023-11-14T22:13:20Z"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = root.join(".traffic-e2e/policy.yaml");
    crate::policy::runtime::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    runtime
        .state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .unwrap()
        .request_contracts
        .request_begin("case")
        .unwrap();
    assert_eq!(
        send(addr, multipart("target-boundary", file), "Bearer secret").await,
        StatusCode::OK
    );
    let report = root.join("replay.json");
    {
        let mut state = runtime.state.lock().await;
        state.finalized_at = Some(Utc::now());
        let bytes = serde_json::to_vec(&state.snapshot_report()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(file));
        std::fs::write(&report, bytes).unwrap();
    }
    task.abort();
    let rule = json!({"id":"multipart-upload","protocol":"http","case":{"method":"POST","path":"/attachments/*"},"target":{"host":"api.example.test","port":80},"source_evidence":"Uploader:build generates a new multipart boundary for each request","http":{"method":"POST","path":"/upload","multipart":{"boundary":"normalize"}}});
    let plan = || {
        plan_dependency_request_rule(DependencyRequestRuleFeedback {
            policy_path: policy.clone(),
            rule: rule.clone(),
            replay_report: report.clone(),
        })
    };
    let error = plan().err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    crate::policy::runtime::install_dependency_rule_fixture(&policy, rule).unwrap();
    assert_eq!(std::fs::read(&dependencies).unwrap(), original);
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    assert_eq!(
        send(addr, multipart("target-boundary", file), "Bearer secret").await,
        StatusCode::OK
    );
    {
        let state = runtime.state.lock().await;
        let report = state.snapshot_report();
        assert!(!report.is_dirty());
        let policy = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(policy.dependency_rules[0].matches, 1);
        assert!(policy.unused_applicable_dependency_rule_ids.is_empty());
    }
    assert_eq!(
        send(addr, multipart("target-boundary", file), "Bearer secret").await,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    for (value, auth, expected) in [
        ("changed", "Bearer secret", StatusCode::BAD_GATEWAY),
        (file, "Bearer changed", StatusCode::BAD_GATEWAY),
    ] {
        let (addr, runtime, task) =
            spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
        assert_eq!(
            send(addr, multipart("target-boundary", value), auth).await,
            expected
        );
        assert!(runtime.state.lock().await.snapshot_report().is_dirty());
        task.abort();
    }
    assert_eq!(std::fs::read(dependencies).unwrap(), original);
}
