//! Key contracts through native TCP Replay, protected plan/apply and finite lanes.
use super::*;
use serde_json::json;
mod generated_queue;

struct Fixture {
    _temp: crate::replay::policy::test_fixture::ManagedFixtureDirectory,
    case: PathBuf,
    policy: PathBuf,
    report: PathBuf,
    immutable: String,
}
impl Fixture {
    fn new(records: Vec<Value>) -> Self {
        let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
        let root = temp.path();
        let local = root.join(".traffic-e2e/local");
        let case = local.join("recordings/run/case");
        std::fs::create_dir_all(&case).unwrap();
        let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(
            key,
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"PUT","uri":"/scenario","timestamp":"1970-01-01T00:16:40Z"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let immutable = records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(case.join("dependencies.jsonl"), &immutable).unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        crate::replay::write_policy_fixture(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        Self {
            case,
            policy,
            report: root.join("replay.json"),
            immutable,
            _temp: temp,
        }
    }
    fn install(&self, id: &str, redis: Value) -> anyhow::Result<()> {
        crate::replay::install_dependency_rule_fixture(
            &self.policy,
            json!({"id":id,"protocol":"redis","target":{"host":"redis.internal","port":6379},
                "case":{"method":"PUT","path":"/scenario"},"source_evidence":"Session:create declares key/JSON identity references and request-relative expiry","redis":redis}),
        )
    }
}
fn session_rule() -> Value {
    json!({"key":{"prefix":"sessions:"},"key_contract":{"kind":"capture","template":"sessions:{value}","format":{"kind":"hex","bytes":2}},
    "commands":[{"command":"SET","argument_values":{"1":{"json":{
        "/id":{"identity":{"template":"{value}"}},
        "/expires_at":{"time":"preserve_relative","format":"unix_seconds"}
    }}}}]})
}
fn ticket_rule() -> Value {
    json!({"key":{"prefix":"tickets:"},"key_contract":{"kind":"capture","template":"tickets:{value}","format":{"kind":"hex","bytes":32}},
    "commands":[{"command":"SET","argument_values":{"1":{"json":{
        "/session_id":{"identity":{"template":"{value}"}}
    }}}}]})
}

#[tokio::test]
async fn redis_generated_keys_plan_in_stages_and_replay_with_consistent_json_references() {
    let conn = Uuid::new_v4();
    let source_ticket = "a".repeat(64);
    let actual_ticket = "b".repeat(64);
    let f = Fixture::new(vec![
        redis_hash_dependency(
            conn,
            1,
            "SET",
            &[
                "sessions:ab12",
                r#"{"id":"ab12","expires_at":4600,"owner":7}"#,
                "EX",
                "3600",
            ],
            b"+OK\r\n",
        ),
        redis_hash_dependency(
            conn,
            2,
            "SET",
            &[
                &format!("tickets:{source_ticket}"),
                r#"{"session_id":"ab12"}"#,
                "EX",
                "60",
            ],
            b"+OK\r\n",
        ),
    ]);
    for stage in 0..4 {
        let (addr, state, task) = redis_value_tests::spawn(&f.case, Some(f.policy.clone())).await;
        state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let session =
            json!({"id":"cd34","expires_at":Utc::now().timestamp()+3600,"owner":7}).to_string();
        let error = b"";
        if stage == 2 {
            let wrong =
                json!({"id":"cd34","expires_at":Utc::now().timestamp()+3600,"owner":8}).to_string();
            redis_value_tests::request(
                &mut client,
                &["SET", "sessions:cd34", &wrong, "EX", "3600"],
                error,
            )
            .await;
            client = TcpStream::connect(addr).await.unwrap();
            assert!(
                state
                    .lock()
                    .await
                    .replay_policy
                    .as_ref()
                    .unwrap()
                    .request_contracts
                    .key_binding_report()
                    .is_empty()
            );
        }
        redis_value_tests::request(
            &mut client,
            &["SET", "sessions:cd34", &session, "EX", "3600"],
            if stage == 0 { error } else { b"+OK\r\n" },
        )
        .await;
        if stage > 0 {
            let ticket_key = format!("tickets:{actual_ticket}");
            let ticket = json!({"session_id":"cd34"}).to_string();
            redis_value_tests::request(
                &mut client,
                &["SET", &ticket_key, &ticket, "EX", "60"],
                if stage == 1 { error } else { b"+OK\r\n" },
            )
            .await;
            if stage == 2 {
                redis_value_tests::request(
                    &mut client,
                    &["SET", &ticket_key, &ticket, "EX", "60"],
                    error,
                )
                .await;
            }
        }
        let report = {
            let mut state = state.lock().await;
            state.finalized_at = Some(Utc::now());
            if stage == 3 {
                assert!(!state.snapshot_report().is_dirty());
            }
            serde_json::to_vec(&state.snapshot_report()).unwrap()
        };
        std::fs::write(&f.report, &report).unwrap();
        task.abort();
        let report: Value = serde_json::from_slice(&report).unwrap();
        if stage == 0 {
            f.install("session-key", session_rule()).unwrap();
        } else if stage == 1 {
            assert_eq!(
                report["replay_policy"]["key_bindings"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            f.install("ticket-key", ticket_rule()).unwrap();
        } else {
            assert_eq!(report["redis"]["matched_count"], 2);
            assert_eq!(report["redis"]["unused_case"].as_array().unwrap().len(), 0);
            assert_eq!(
                report["replay_policy"]["key_bindings"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                report["redis"]["unmatched"].as_array().unwrap().len(),
                if stage == 2 { 2 } else { 0 }
            );
        }
        assert_eq!(
            crate::recorder::test_io::read_to_string_sync(f.case.join("dependencies.jsonl"))
                .unwrap(),
            f.immutable
        );
    }
}

#[tokio::test]
async fn redis_key_window_preserves_multi_exec_order_and_finite_command_consumption() {
    let conn = Uuid::new_v4();
    let f = Fixture::new(vec![
        redis_hash_dependency(conn, 1, "MULTI", &[], b"+OK\r\n"),
        redis_hash_dependency(conn, 2, "INCRBY", &["rate:user:16", "1"], b"+QUEUED\r\n"),
        redis_hash_dependency(conn, 3, "EXPIRE", &["rate:user:16", "61"], b"+QUEUED\r\n"),
        redis_hash_dependency(conn, 4, "EXEC", &[], b"*2\r\n:1\r\n:1\r\n"),
    ]);
    for applied in [false, true] {
        let (addr, state, task) = redis_value_tests::spawn(&f.case, Some(f.policy.clone())).await;
        state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        let key = format!("rate:user:{}", Utc::now().timestamp().div_euclid(60));
        let mut client = TcpStream::connect(addr).await.unwrap();
        redis_value_tests::request(&mut client, &["MULTI"], b"+OK\r\n").await;
        let error = b"";
        redis_value_tests::request(
            &mut client,
            &["INCRBY", &key, "1"],
            if applied { b"+QUEUED\r\n" } else { error },
        )
        .await;
        if applied {
            redis_value_tests::request(&mut client, &["EXPIRE", &key, "61"], b"+QUEUED\r\n").await;
            redis_value_tests::request(&mut client, &["EXEC"], b"*2\r\n:1\r\n:1\r\n").await;
        }
        let report = {
            let mut state = state.lock().await;
            state.finalized_at = Some(Utc::now());
            serde_json::to_vec(&state.snapshot_report()).unwrap()
        };
        std::fs::write(&f.report, &report).unwrap();
        task.abort();
        if !applied {
            f.install("window",json!({"key":{"prefix":"rate:"},"key_contract":{"kind":"time_window","window_seconds":60},
                "commands":[{"command":"INCRBY","argument_values":{}},{"command":"EXPIRE","argument_values":{}}]})).unwrap();
        } else {
            let report: Value = serde_json::from_slice(&report).unwrap();
            assert_eq!(report["redis"]["matched_count"], 4);
            assert!(report["redis"]["unmatched"].as_array().unwrap().is_empty());
            assert!(
                report["redis"]["unused_case"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
    }
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(f.case.join("dependencies.jsonl")).unwrap(),
        f.immutable
    );
}
