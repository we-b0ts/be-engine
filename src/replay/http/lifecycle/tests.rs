use super::*;
use crate::replay::ReplayExchangeStatus;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn dependency(id: uuid::Uuid, prefix: bool) -> Value {
    let mut value = serde_json::json!({
        "event_type":"http_exchange", "id":id,"scheme":"http", "method":"POST",
        "uri":"/pending", "authority":"lifecycle.test", "duration_ms":25,
        "request_body":{"encoding":"utf8","truncated":false,"data":""},
        "response_status":null, "response_headers":null,"response_body":null,
        "error":"HTTP dependency capture cancelled without observed client termination",
        "outcome":"response"
    });
    if prefix {
        value["response_status"] = serde_json::json!(200);
        value["response_headers"] = serde_json::json!({"content-type":["text/event-stream"]});
        value["response_body"] =
            serde_json::json!({"encoding":"utf8","truncated":false,"data":"one"});
        value["response_stream"] = serde_json::json!({"version":2,"headers_ms":0,
            "chunks":[{"at_ms":1,"start":0,"end":3}],"end_ms":25,"complete":false});
        value["error"] = serde_json::json!(ENGINE_CLEANUP);
    }
    value
}

#[tokio::test]
async fn source_stop_cleanup_holds_missing_response_and_flushed_prefix_until_real_target_end() {
    for prefix in [false, true] {
        exercise(prefix, false).await;
    }
}

#[tokio::test]
async fn target_termination_before_source_stop_boundary_remains_a_failure() {
    exercise(false, true).await;
}

async fn exercise(prefix: bool, early: bool) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("lifecycle-case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let id = uuid::Uuid::new_v4();
    let reference = serde_json::json!({"protocol":"http","exchange_id":id});
    let original = dependency(id, prefix);
    tokio::fs::write(case.join("dependencies.jsonl"), original.to_string())
        .await
        .unwrap();
    tokio::fs::write(
        case.join("async-api-observation.json"),
        serde_json::json!({
            "version":2,"capture_complete":true,"business_complete":false,"business_completion":"unobserved","inventory_complete":true,"end_reason":"timeout",
            "request_timeout_ms":1000,"source_stop_required":true,"source_stop_after_ms":0,
            "completed_refs":[reference.clone()],"cleanup_refs":[reference]
        })
        .to_string(),
    )
    .await
    .unwrap();
    let (address, runtime, task) =
        crate::replay::http::tests::spawn_http_replay(&case, vec![]).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"POST /pending HTTP/1.1\r\nHost: lifecycle.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    if prefix {
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !received.windows(3).any(|window| window == b"one") {
                received.push(client.read_u8().await.unwrap());
            }
        })
        .await
        .unwrap();
        let text = String::from_utf8(received).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(!text.to_ascii_lowercase().contains("content-length:"));
        let mut suffix = [0; 2];
        client.read_exact(&mut suffix).await.unwrap();
        assert_eq!(&suffix, b"\r\n");
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.state.lock().await.http_exchange_status(0)
                == Some(ReplayExchangeStatus::AwaitingClientTermination)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(40), client.read(&mut byte))
            .await
            .is_err(),
        "cleanup must not synthesize a proxy 502 or response EOF"
    );
    {
        let mut state = runtime.state.lock().await;
        assert_eq!(state.protocols.http_events.matched_count, 0);
        assert_eq!(
            state.protocols.http_exchanges[0].record.native.outcome,
            crate::DependencyExchangeOutcome::Response
        );
        assert_eq!(
            state.protocols.http_exchanges[0]
                .record
                .native
                .error
                .as_deref(),
            original["error"].as_str()
        );
        if !early {
            state
                .async_cleanup_gate(
                    "lifecycle-case",
                    crate::replay::control::dependency_tail::RecordedReference::Http {
                        exchange_id: id,
                    },
                )
                .unwrap()
                .store(true, Ordering::Release);
            state.target_stop_prepared.insert("lifecycle-case".into());
        }
    }
    // The lifecycle gate alone does not consume the request: real Target IO ends it.
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .http_events
            .matched_count,
        0
    );
    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let status = runtime.state.lock().await.protocols.http_exchanges[0].status;
            if matches!(
                status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert_eq!(
        state.protocols.http_exchanges[0].status,
        if early {
            ReplayExchangeStatus::Failed
        } else {
            ReplayExchangeStatus::Consumed
        }
    );
    assert_eq!(
        state.protocols.http_events.matched_count,
        usize::from(!early)
    );
    drop(state);
    task.abort();
}

#[test]
fn cleanup_authorization_does_not_accept_capture_limits_or_complete_business_errors() {
    for prefix in [false, true] {
        let mut record: RecordedHttpExchange =
            serde_json::from_value(dependency(uuid::Uuid::new_v4(), prefix)).unwrap();
        record.authorize_lifecycle_cleanup().unwrap();
        if prefix {
            record.native.error =
                Some("HTTP dependency stream exceeded its byte or chunk capture limit".into());
        } else {
            record.native.response_status = Some(502);
            record.native.response_headers = Some(Default::default());
        }
        assert!(record.authorize_lifecycle_cleanup().is_err());
    }
}

#[tokio::test]
async fn cleanup_prefix_reuses_staged_request_identity_and_keeps_incomplete_source_evidence() {
    let temporary = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temporary.path().join("prefix-echo");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let id = uuid::Uuid::new_v4();
    let source_id = "0123456789ab4def8123456789abcdef";
    let target_id = "fedcba98765443218123456789abcdef";
    let source_body = format!("{{\"id\":\"{source_id}\"}}");
    let target_body = format!("{{\"id\":\"{target_id}\"}}");
    let source_prefix = format!("data: {source_body}\n\n");
    let mut original = dependency(id, true);
    original["request_body"]["data"] = serde_json::json!(source_body);
    original["response_body"]["data"] = serde_json::json!(source_prefix);
    original["response_stream"]["chunks"][0]["end"] = serde_json::json!(source_prefix.len());
    tokio::fs::write(case.join("dependencies.jsonl"), original.to_string())
        .await
        .unwrap();
    let reference = serde_json::json!({"protocol":"http","exchange_id":id});
    tokio::fs::write(
        case.join("async-api-observation.json"),
        serde_json::json!({
            "version":2,"capture_complete":true,"business_complete":false,"business_completion":"unobserved","inventory_complete":true,"end_reason":"timeout",
            "request_timeout_ms":1000,"source_stop_required":true,"source_stop_after_ms":0,
            "completed_refs":[reference.clone()],"cleanup_refs":[reference]
        })
        .to_string(),
    )
    .await
    .unwrap();
    tokio::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/main"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(case.join("expected-response.json"), "{}")
        .await
        .unwrap();
    let policy = temporary.path().join("policy.yaml");
    tokio::fs::write(&policy,"format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [{hex: 32}]}\n").await.unwrap();
    let (address, runtime, task) = crate::replay::http::tests::spawn_http_replay_with_policy(
        &case,
        vec![],
        Some(policy),
        None,
    )
    .await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(format!("POST /pending HTTP/1.1\r\nHost: lifecycle.test\r\nContent-Length: {}\r\n\r\n{target_body}",target_body.len()).as_bytes()).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !received
            .windows(target_id.len())
            .any(|bytes| bytes == target_id.as_bytes())
        {
            received.push(client.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(!String::from_utf8_lossy(&received).contains(source_id));
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.http_events.matched_count, 0);
    assert!(
        !state.protocols.http_exchanges[0]
            .record
            .native
            .response_stream
            .as_ref()
            .unwrap()
            .complete
    );
    assert_eq!(
        decode_body(
            state.protocols.http_exchanges[0]
                .record
                .native
                .response_body
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        source_prefix.as_bytes()
    );
    drop(state);
    task.abort();
}

#[tokio::test]
async fn dependency_failure_allows_natural_target_eof_only_after_all_ordinary_resources_finish() {
    for unconsumed in [false, true] {
        natural_failure_eof(unconsumed).await;
    }
}

async fn natural_failure_eof(unconsumed: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let case = temporary.path().join("failure-eof");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let pending_id = uuid::Uuid::new_v4();
    let failure_id = uuid::Uuid::new_v4();
    let mut failure = dependency(failure_id, false);
    failure["uri"] = serde_json::json!("/failure");
    failure["error"] = Value::Null;
    failure["response_status"] = serde_json::json!(503);
    failure["response_headers"] = serde_json::json!({});
    failure["response_body"] =
        serde_json::json!({"encoding":"utf8","truncated":false,"data":"failed"});
    let mut records = vec![dependency(pending_id, false), failure.clone()];
    let cleanup = serde_json::json!({"protocol":"http","exchange_id":pending_id});
    let mut references = vec![
        cleanup.clone(),
        serde_json::json!({"protocol":"http","exchange_id":failure_id}),
    ];
    if unconsumed {
        let extra_id = uuid::Uuid::new_v4();
        failure["id"] = serde_json::json!(extra_id);
        failure["uri"] = serde_json::json!("/must-also-finish");
        failure["response_status"] = serde_json::json!(200);
        records.push(failure);
        references.push(serde_json::json!({"protocol":"http","exchange_id":extra_id}));
    }
    tokio::fs::write(
        case.join("dependencies.jsonl"),
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .await
    .unwrap();
    tokio::fs::write(
        case.join("async-api-observation.json"),
        serde_json::json!({
            "version":2,"capture_complete":true,"business_complete":false,"business_completion":"unobserved","inventory_complete":true,"end_reason":"dependency_failure",
            "request_timeout_ms":1000,"source_stop_required":true,"source_stop_after_ms":900,
            "completed_refs":references,"cleanup_refs":[cleanup]
        })
        .to_string(),
    )
    .await
    .unwrap();
    let (address, runtime, task) =
        crate::replay::http::tests::spawn_http_replay(&case, vec![]).await;
    let mut pending = TcpStream::connect(address).await.unwrap();
    pending
        .write_all(b"POST /pending HTTP/1.1\r\nHost: lifecycle.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.state.lock().await.http_exchange_status(0)
                == Some(ReplayExchangeStatus::AwaitingClientTermination)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let response = crate::replay::http::tests::send_request(
        TokioIo::new(TcpStream::connect(address).await.unwrap()),
        "lifecycle.test",
        "/failure",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    response.into_body().collect().await.unwrap();
    // Target legitimately cancels its other call as soon as it receives the
    // Source-proven business failure, before prepare_end's polling interval.
    pending.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if matches!(
                runtime.state.lock().await.protocols.http_exchanges[0].status,
                ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Failed
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = runtime.state.lock().await;
    assert_eq!(
        state.protocols.http_exchanges[0].status,
        if unconsumed {
            ReplayExchangeStatus::Failed
        } else {
            ReplayExchangeStatus::Consumed
        }
    );
    assert!(!state.target_stop_prepared.contains("failure-eof"));
    assert!(
        !state.target_session_stopped,
        "natural EOF is no controller stop receipt"
    );
    assert_eq!(state.active_case_id.as_deref(), Some("failure-eof"));
    if unconsumed {
        assert_eq!(
            state.protocols.http_exchanges[2].status,
            ReplayExchangeStatus::Available
        );
    }
    drop(state);
    task.abort();
}
