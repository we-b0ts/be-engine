//! Actual RESP client verifies discovery, authoring and finite correlated replay.
use super::*;
use redis_value_tests::{request, spawn};
#[tokio::test]
async fn scalar_formats_share_complete_values_with_script_argv_without_special_lock_semantics() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("apis/delete/case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let lane = Uuid::new_v4();
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let set = redis_hash_dependency(
        lane,
        1,
        "SET",
        &[
            "lock:item:1",
            "11111111111111111111111111111111",
            "NX",
            "EX",
            "30",
        ],
        b"+OK\r\n",
    );
    let mut read = redis_hash_dependency(
        lane,
        2,
        "MGET",
        &["item:online:1", "item:online:legacy"],
        b"*2\r\n$-1\r\n$-1\r\n",
    );
    read["response_kind"] = "array".into();
    let release = redis_hash_dependency(
        lane,
        3,
        "EVALSHA",
        &[sha, "1", "lock:item:1", "11111111111111111111111111111111"],
        b":1\r\n",
    );
    let dependencies = case.join("dependencies.jsonl");
    let records = [set, read, release].map(|mut event| {
        event["timestamp"] = serde_json::json!("1970-01-01T00:16:40Z");
        event["request_started_at"] = event["timestamp"].clone();
        event["duration_ms"] = serde_json::json!(0);
        event
    });
    std::fs::write(
        &dependencies,
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let immutable = std::fs::read(&dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"DELETE","uri":"/item/1"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let policy = temp.path().join("policy.yaml");
    std::fs::write(
        &policy,
        r#"format: traffic-policy/v3
redis:
  keys:
    'lock:item:*': {kind: identity, formats: [{hex: 32}]}
"#,
    )
    .unwrap();
    let (addr, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut reader = TcpStream::connect(addr).await.unwrap();
    let mut releaser = TcpStream::connect(addr).await.unwrap();
    let error = b"";
    request(
        &mut client,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        error,
    )
    .await;
    client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &[
            "SET",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "NX",
            "EX",
            "31",
        ],
        error,
    )
    .await;
    client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &[
            "SET",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "NX",
            "EX",
            "30",
        ],
        b"+OK\r\n",
    )
    .await;
    request(
        &mut releaser,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        error,
    )
    .await;
    releaser = TcpStream::connect(addr).await.unwrap();
    request(
        &mut reader,
        &["MGET", "item:online:1", "item:online:legacy"],
        b"*2\r\n$-1\r\n$-1\r\n",
    )
    .await;
    drop(client);
    request(
        &mut releaser,
        &["EVALSHA", sha, "1", "lock:item:1", "wrong-token"],
        error,
    )
    .await;
    releaser = TcpStream::connect(addr).await.unwrap();
    request(
        &mut releaser,
        &[
            "EVALSHA",
            "changed-script",
            "1",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        error,
    )
    .await;
    releaser = TcpStream::connect(addr).await.unwrap();
    request(
        &mut releaser,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        b":1\r\n",
    )
    .await;
    request(
        &mut releaser,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ],
        error,
    )
    .await;
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 3);
    assert_eq!(report["redis"]["connections"], 8);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(std::fs::read(dependencies).unwrap(), immutable);
    task.abort();
}
