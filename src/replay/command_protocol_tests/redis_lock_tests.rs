//! Actual RESP client verifies discovery, authoring and finite correlated replay.
use super::*;
use crate::{RedisLockFeedback, RedisLockSelector, RedisValueKeySelector, plan_redis_lock};
use redis_value_tests::{request, spawn};
#[tokio::test]
async fn redis_lock_discovery_plan_apply_then_actual_set_evalsha_keeps_token_and_script_identity() {
    let temp = tempfile::tempdir().unwrap();
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
        &["lock:item:1", "source-opaque-nonce", "NX", "EX", "30"],
        b"+OK\r\n",
    );
    let release = redis_hash_dependency(
        lane,
        2,
        "EVALSHA",
        &[sha, "1", "lock:item:1", "source-opaque-nonce"],
        b":1\r\n",
    );
    let dependencies = case.join("dependencies.jsonl");
    std::fs::write(&dependencies, format!("{set}\n{release}\n")).unwrap();
    let immutable = std::fs::read(&dependencies).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"DELETE","uri":"/item/1"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let (addr, state, task) = spawn(&case, None).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &[
            "SET",
            "lock:item:1",
            "target-different-format-nonce",
            "NX",
            "EX",
            "30",
        ],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    let report = temp.path().join("replay.json");
    {
        let mut state = state.lock().await;
        state.finalized_at = Some(Utc::now());
        std::fs::write(
            &report,
            serde_json::to_vec(&state.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let policy = temp.path().join("verification.yaml");
    std::fs::write(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    plan_redis_lock(RedisLockFeedback {
        policy_path: policy.clone(),
        case_source: case.clone(),
        replay_report_path: report,
        rule_id: "item-lock".into(),
        selector: RedisLockSelector {
            host: "redis.internal".into(),
            port: 6379,
            key: RedisValueKeySelector::Affix {
                prefix: "lock:item:".into(),
                suffix: String::new(),
            },
        },
        source_evidence: "LockStore.java:acquire/release uses random token and conditional delete"
            .into(),
    })
    .unwrap()
    .apply()
    .unwrap();
    let (addr, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let error = b"-ERR no recorded Redis dependency matched\r\n";
    request(
        &mut client,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "target-different-format-nonce",
        ],
        error,
    )
    .await;
    request(
        &mut client,
        &[
            "SET",
            "lock:item:1",
            "target-different-format-nonce",
            "NX",
            "EX",
            "31",
        ],
        error,
    )
    .await;
    request(
        &mut client,
        &[
            "SET",
            "lock:item:1",
            "target-different-format-nonce",
            "NX",
            "EX",
            "30",
        ],
        b"+OK\r\n",
    )
    .await;
    request(
        &mut client,
        &["EVALSHA", sha, "1", "lock:item:1", "wrong-token"],
        error,
    )
    .await;
    request(
        &mut client,
        &[
            "EVALSHA",
            "changed-script",
            "1",
            "lock:item:1",
            "target-different-format-nonce",
        ],
        error,
    )
    .await;
    request(
        &mut client,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "target-different-format-nonce",
        ],
        b":1\r\n",
    )
    .await;
    request(
        &mut client,
        &[
            "EVALSHA",
            sha,
            "1",
            "lock:item:1",
            "target-different-format-nonce",
        ],
        error,
    )
    .await;
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 2);
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["redis"]["lock_tokens"]["candidates"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        report["replay_policy"]["dependency_rules"][0]["validations"],
        2
    );
    assert_eq!(std::fs::read(dependencies).unwrap(), immutable);
    task.abort();
}
