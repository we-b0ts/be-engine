//! HTTP JSON time contracts through protected planning and real replay requests.
use super::*;
use serde_json::json;
#[path = "json_request_time/pairing.rs"]
mod pairing;

async fn send(addr: SocketAddr, uri: &str, body: String, auth: &str) -> StatusCode {
    send_response(addr, uri, body, auth).await.0
}

async fn send_response(
    addr: SocketAddr,
    uri: &str,
    body: String,
    auth: &str,
) -> (StatusCode, Bytes) {
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
                .uri(uri)
                .header("host", "api.example.test")
                .header("content-type", "application/json")
                .header("authorization", auth)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}
fn body(end: i64) -> Value {
    json!({"query":"private-expression", "start":end-300, "end":end, "step":"1m", "ordered":[1,2]})
}
fn rule() -> Value {
    json!({"format":"traffic-policy/v2","json":{"fields":{
        "/start":{"kind":"time","formats":["unix_seconds"]},
        "/end":{"kind":"time","formats":["unix_seconds"]}
    }}})
}

#[tokio::test]
async fn json_time_plan_apply_and_fresh_replay_preserve_contracts_and_consumption() {
    let temp = tempdir().unwrap();
    let root = temp.path();
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
        "/query?mode=original",
        &body(1_700_000_000).to_string(),
        "recorded-result",
    )
    .await;
    let dependencies = case.join("dependencies.jsonl");
    let mut source: Value = serde_json::from_slice(&std::fs::read(&dependencies).unwrap()).unwrap();
    source["request_started_at"] = json!("2023-11-14T22:13:20.125Z");
    source["request_headers"] =
        json!({"content-type":["application/json"],"authorization":["Bearer secret"]});
    std::fs::write(&dependencies, format!("{source}\n")).unwrap();
    let original = std::fs::read(&dependencies).unwrap();
    // Deliberately distant inbound clock: the outbound dependency must use its own anchor.
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/windows/1","timestamp":"2023-11-14T22:00:00Z"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = root.join(".traffic-e2e/policy.yaml");
    crate::replay::write_policy_fixture(
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
        send(
            addr,
            "/query?mode=original",
            body(Utc::now().timestamp()).to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    let report = root.join("replay.json");
    {
        let mut state = runtime.state.lock().await;
        state.finalized_at = Some(Utc::now());
        let value = serde_json::to_value(state.snapshot_report()).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private-expression"));
        assert!(!String::from_utf8_lossy(&bytes).contains("mode=original"));
        std::fs::write(&report, bytes).unwrap();
    }
    task.abort();
    crate::replay::write_policy_fixture(&policy, rule().to_string()).unwrap();
    assert_eq!(std::fs::read(&dependencies).unwrap(), original);

    // Rejections must not consume the recorded response or increment successful validations.
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec!["mode".into()], Some(policy.clone()), None).await;
    let valid = body(Utc::now().timestamp());
    for (pointer, value) in [
        ("/start", json!(valid["start"].as_i64().unwrap() + 6)),
        ("/end", json!(valid["end"].to_string())),
        ("/step", json!("5m")),
        ("/query", json!("different")),
        ("/ordered", json!([2, 1])),
        ("/extra", json!(1)),
        ("/start", Value::Null),
    ] {
        let mut invalid = valid.clone();
        invalid[pointer.trim_start_matches('/')] = value;
        assert_eq!(
            send(
                addr,
                "/query?mode=original",
                invalid.to_string(),
                "Bearer secret"
            )
            .await,
            StatusCode::BAD_GATEWAY
        );
    }
    for (uri, body, auth) in [
        ("/query?mode=changed", valid.to_string(), "Bearer secret"),
        ("/other?mode=original", valid.to_string(), "Bearer secret"),
        (
            "/query?mode=original",
            format!(
                "{{\"end\":{},\"end\":{},\"start\":{}}}",
                valid["end"], valid["end"], valid["start"]
            ),
            "Bearer secret",
        ),
    ] {
        assert_eq!(send(addr, uri, body, auth).await, StatusCode::BAD_GATEWAY);
    }
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .global_formats[0]
            .validations,
        0
    );
    let valid = body(Utc::now().timestamp());
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            valid.to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::OK
    );
    {
        let state = runtime.state.lock().await;
        let policy = state.replay_policy.as_ref().unwrap().report();
        assert_eq!(policy.global_formats[0].validations, 1);
        assert_eq!(policy.global_formats[0].time_validations, 2);
        assert!(policy.unused_applicable_dependency_rule_ids.is_empty());
    }
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            valid.to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    task.abort();
    // A clean fresh replay succeeds without an inbound clock, since only dependency time is used.
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            body(Utc::now().timestamp()).to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
    // Body rules retain the native credential-presence contract. Credential
    // bytes remain protected evidence and are not promoted to a literal rule.
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            body(Utc::now().timestamp()).to_string(),
            "Bearer different"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
    // Older recordings use completion minus recorded duration, never the current clock.
    let mut legacy = source.clone();
    legacy.as_object_mut().unwrap().remove("request_started_at");
    legacy["timestamp"] = json!("2023-11-14T22:13:21.125Z");
    legacy["duration_ms"] = json!(1000);
    std::fs::write(&dependencies, format!("{legacy}\n")).unwrap();
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy.clone()), None).await;
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            body(Utc::now().timestamp()).to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::OK
    );
    assert!(!runtime.state.lock().await.snapshot_report().is_dirty());
    task.abort();
    legacy.as_object_mut().unwrap().remove("duration_ms");
    std::fs::write(&dependencies, format!("{legacy}\n")).unwrap();
    // Equal values need no clocks. A differing time still cannot borrow an anchor.
    let (addr, runtime, task) =
        spawn_http_replay_with_policy(&case, vec![], Some(policy), None).await;
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            body(Utc::now().timestamp()).to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        send(
            addr,
            "/query?mode=original",
            body(1_700_000_000).to_string(),
            "Bearer secret"
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .report()
            .global_formats[0]
            .time_validations,
        0
    );
    task.abort();
    std::fs::write(&dependencies, &original).unwrap();
    assert_eq!(std::fs::read(&dependencies).unwrap(), original);
}
