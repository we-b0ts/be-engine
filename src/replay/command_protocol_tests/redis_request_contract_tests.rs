//! Redis request discovery, protected planning and finite Replay over actual TCP.
use super::*;
use crate::{DependencyRequestRuleFeedback, plan_dependency_request_rule};
use serde_json::json;

fn token(claims: Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"test-key"),
    )
    .unwrap()
}
fn session(now: i64, nonce: &str) -> String {
    json!({"approved_at":now,"access_token":token(json!({"sub":"user","exp":now+3600})),"refresh_token":token(json!({"sub":"user","exp":now+7200,"jti":nonce})),"status":"approved"}).to_string()
}
fn rule(jwt: bool) -> Value {
    let redis = if jwt {
        let jwt = json!({"jwt":{"signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"algorithm":"HS256","relative_to":"/approved_at"}});
        let mut refresh = jwt.clone();
        refresh["jwt"]["dynamic_claims"] = json!(["/jti"]);
        json!({"key":{"prefix":"session:"},"commands":[{"command":"SET","argument_values":{"1":{"json":{"/approved_at":{"time":"preserve_relative","format":"unix_seconds"},"/access_token":jwt,"/refresh_token":refresh}}}}]})
    } else {
        json!({"key":{"prefix":"presence:","numeric":true},"commands":[{"command":"ZADD","argument_values":{"1":{"time":"preserve_relative","format":"unix_seconds"}}},{"command":"ZREMRANGEBYSCORE","argument_values":{"2":{"time":"preserve_relative","format":"unix_seconds"}}}]})
    };
    json!({"id":"request-contract","protocol":"redis","target":{"host":"redis.internal","port":6379},"case":{"method":"PUT","path":"/scenario"},"source_evidence":"Service:update generates current timestamps and signed JWTs using the startup key","redis":redis})
}

#[tokio::test]
async fn redis_rfc3339_time_rule_replays_finitely_and_rejects_changed_offsets() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"PUT","uri":"/scenario","timestamp":"1970-01-01T00:16:40Z"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let source = r#"{"last_activity_at":"1970-01-01T08:16:40+08:00","status":"running"}"#;
    let record = redis_hash_dependency(
        Uuid::new_v4(),
        1,
        "SET",
        &["streaming:1", source],
        b"+OK\r\n",
    );
    let path = case.join("dependencies.jsonl");
    let immutable = record.to_string();
    std::fs::write(&path, &immutable).unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(&policy,json!({"version":3,"expected_response":"assertions_only","dependency_rules":[{
        "id":"activity-time","protocol":"redis","case":{"method":"PUT","path":"/scenario"},
        "target":{"host":"redis.internal","port":6379},"source_evidence":"Session:touch writes datetime.now(timezone.utc).isoformat()",
        "redis":{"key":{"prefix":"streaming:","numeric":true},"commands":[{"command":"SET","argument_values":{"1":{"json":{"/last_activity_at":{"time":"preserve_relative","format":"rfc3339"}}}}}]}
    }]}).to_string()).unwrap();
    let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy)).await;
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
    for (seconds, status, passes) in [
        (60, "running", false),
        (0, "stopped", false),
        (0, "running", true),
        (0, "running", false),
    ] {
        let timestamp = (Utc::now() + chrono::Duration::seconds(seconds))
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .to_rfc3339();
        let actual = json!({"last_activity_at":timestamp,"status":status}).to_string();
        redis_value_tests::request(
            &mut client,
            &["SET", "streaming:1", &actual],
            if passes {
                b"+OK\r\n"
            } else {
                b"-ERR no recorded Redis dependency matched\r\n"
            },
        )
        .await;
    }
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(path).unwrap(),
        immutable
    );
    task.abort();
}

#[tokio::test]
async fn redis_request_contracts_discover_plan_apply_and_verify_json_jwts_and_fractional_time_sequence()
 {
    for jwt in [false, true] {
        let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
        let root = temp.path();
        let local = root.join(".traffic-e2e/local");
        let case = local.join("recordings/run/case");
        std::fs::create_dir_all(&case).unwrap();
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        let key = std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV)
            .unwrap_or_else(|_| STANDARD.encode([7u8; 32]));
        std::fs::write(key_path, key).unwrap();
        std::fs::write(local.join("target.env"), "SECRET_KEY=test-key\n").unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"PUT","uri":"/scenario","timestamp":"1970-01-01T00:16:40Z"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let connection = Uuid::new_v4();
        let records = if jwt {
            vec![redis_hash_dependency(
                connection,
                1,
                "SET",
                &[
                    "session:1",
                    &session(1000, "d9428888-122b-4d10-9c62-0b7bdca327a1"),
                    "EX",
                    "300",
                ],
                b"+OK\r\n",
            )]
        } else {
            vec![
                redis_hash_dependency(
                    connection,
                    1,
                    "ZADD",
                    &["presence:1", "1090.25", "active"],
                    b":1\r\n",
                ),
                redis_hash_dependency(
                    connection,
                    2,
                    "ZREMRANGEBYSCORE",
                    &["presence:1", "-inf", "1000.25"],
                    b":0\r\n",
                ),
            ]
        };
        let immutable = records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let dependencies = case.join("dependencies.jsonl");
        std::fs::write(&dependencies, &immutable).unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        crate::replay::write_policy_fixture(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let make_request = || {
            let now = Utc::now();
            if jwt {
                vec![
                    "SET".into(),
                    "session:1".into(),
                    session(now.timestamp(), "bf54c745-3da7-4ebc-9c32-fda7fd5a9bd2"),
                    "EX".into(),
                    "300".into(),
                ]
            } else {
                vec![
                    "ZADD".into(),
                    "presence:1".into(),
                    format!(
                        "{}",
                        now.timestamp() as f64
                            + f64::from(now.timestamp_subsec_nanos()) / 1e9
                            + 90.0
                    ),
                    "active".into(),
                ]
            }
        };
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
        state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        let actual = make_request();
        let mut client = TcpStream::connect(addr).await.unwrap();
        redis_value_tests::request(
            &mut client,
            &actual.iter().map(String::as_str).collect::<Vec<_>>(),
            b"-ERR no recorded Redis dependency matched\r\n",
        )
        .await;
        let report = root.join("replay.json");
        let report_bytes = {
            let mut state = state.lock().await;
            state.finalized_at = Some(Utc::now());
            serde_json::to_vec(&state.snapshot_report()).unwrap()
        };
        assert!(!String::from_utf8_lossy(&report_bytes).contains("test-key"));
        if jwt {
            assert!(!String::from_utf8_lossy(&report_bytes).contains(&actual[2]));
        }
        std::fs::write(&report, &report_bytes).unwrap();
        task.abort();
        let error = plan_dependency_request_rule(DependencyRequestRuleFeedback {
            policy_path: policy.clone(),
            rule: rule(jwt),
            replay_report: report.clone(),
        })
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("legacy rule authoring is retired")
        );
        crate::replay::install_dependency_rule_fixture(&policy, rule(jwt)).unwrap();
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
        state
            .lock()
            .await
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .request_begin("case")
            .unwrap();
        let actual = make_request();
        let mut client = TcpStream::connect(addr).await.unwrap();
        redis_value_tests::request(
            &mut client,
            &actual.iter().map(String::as_str).collect::<Vec<_>>(),
            if jwt { b"+OK\r\n" } else { b":1\r\n" },
        )
        .await;
        if !jwt {
            let cutoff = (actual[2].parse::<f64>().unwrap() - 90.0).to_string();
            redis_value_tests::request(
                &mut client,
                &["ZREMRANGEBYSCORE", "presence:1", "-inf", &cutoff],
                b":0\r\n",
            )
            .await;
        }
        let replay = state.lock().await;
        assert!(!replay.snapshot_report().is_dirty());
        let usage = replay.replay_policy.as_ref().unwrap().report();
        assert_eq!(usage.dependency_rules[0].matches, if jwt { 1 } else { 2 });
        assert!(usage.unused_applicable_dependency_rule_ids.is_empty());
        drop(replay);
        redis_value_tests::request(
            &mut client,
            &actual.iter().map(String::as_str).collect::<Vec<_>>(),
            b"-ERR no recorded Redis dependency matched\r\n",
        )
        .await;
        assert_eq!(
            crate::recorder::test_io::read_to_string_sync(&dependencies).unwrap(),
            immutable
        );
        task.abort();
    }
}

#[tokio::test]
async fn script_and_rpush_contracts_plan_apply_and_replay_over_real_redis_clients() {
    for script in [true, false] {
        let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
        let root = temp.path();
        let local = root.join(".traffic-e2e/local");
        let case = local.join("recordings/run/case");
        std::fs::create_dir_all(&case).unwrap();
        let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(
            key_path,
            std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV)
                .unwrap_or_else(|_| STANDARD.encode([7u8; 32])),
        )
        .unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"PUT","uri":"/scenario","timestamp":"1970-01-01T00:16:40Z"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let command = if script { "EVALSHA" } else { "RPUSH" };
        let source_args = if script {
            vec![sha, "1", "events", "1000000", "stable"]
        } else {
            vec!["events", r#"{"id":1,"timestamp":1000,"stable":"keep"}"#]
        };
        let record = redis_hash_dependency(Uuid::new_v4(), 1, command, &source_args, b":1\r\n");
        let immutable = record.to_string();
        std::fs::write(case.join("dependencies.jsonl"), &immutable).unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        crate::replay::write_policy_fixture(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let report = root.join("replay.json");
        let request = || {
            let now = Utc::now();
            if script {
                vec![
                    command.into(),
                    sha.into(),
                    "1".into(),
                    "events".into(),
                    now.timestamp_millis().to_string(),
                    "stable".into(),
                ]
            } else {
                vec![
                    command.into(),
                    "events".into(),
                    json!({"id":9,"timestamp":now.timestamp(),"stable":"keep"}).to_string(),
                ]
            }
        };
        // RPUSH first captures its ID. Both families then plan a time contract
        // from a fresh protected witness under the currently applied policy.
        for identity_phase in if script {
            vec![false]
        } else {
            vec![true, false]
        } {
            let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
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
            let actual = request();
            redis_value_tests::request(
                &mut client,
                &actual.iter().map(String::as_str).collect::<Vec<_>>(),
                b"-ERR no recorded Redis dependency matched\r\n",
            )
            .await;
            {
                let mut replay = state.lock().await;
                replay.finalized_at = Some(Utc::now());
                std::fs::write(
                    &report,
                    serde_json::to_vec(&replay.snapshot_report()).unwrap(),
                )
                .unwrap();
            }
            task.abort();
            if identity_phase {
                crate::replay::install_dependency_rule_fixture(&policy, json!({"kind":"dynamic_value","id":"event-id","api":"/scenario","value_type":"integer","targets":[{"host":"redis.internal","port":6379}],"capture":{"protocol":"redis","target":{"host":"redis.internal","port":6379},"database":0,"command":"RPUSH","key":"events","argument_index":1,"json_pointer":"/id"},"source_evidence":"Emitter:enqueue generates one integer ID for its emitted event"})).unwrap();
            } else {
                let redis = if script {
                    json!({"key":"events","commands":[{"command":"EVALSHA","script":{"sha1":sha},"argument_values":{"3":{"time":"preserve_relative","format":"unix_milliseconds"}}}]})
                } else {
                    json!({"key":"events","commands":[{"command":"RPUSH","argument_values":{"1":{"json":{"/timestamp":{"time":"preserve_relative","format":"unix_seconds"}}}}}]})
                };
                let rule = json!({"id":"event-time","protocol":"redis","target":{"host":"redis.internal","port":6379},"case":{"method":"PUT","path":"/scenario"},"source_evidence":"Emitter:enqueue writes the current request time to Redis","redis":redis});
                crate::replay::install_dependency_rule_fixture(&policy, rule).unwrap();
            }
        }
        let (addr, state, task) = redis_value_tests::spawn(&case, Some(policy.clone())).await;
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
        let actual = request();
        redis_value_tests::request(
            &mut client,
            &actual.iter().map(String::as_str).collect::<Vec<_>>(),
            b":1\r\n",
        )
        .await;
        {
            let replay = state.lock().await;
            assert!(!replay.snapshot_report().is_dirty());
            let usage = replay.replay_policy.as_ref().unwrap().report();
            assert!(usage.dependency_rules.iter().all(|r| r.matches > 0));
            assert!(usage.unused_applicable_dependency_rule_ids.is_empty());
        }
        redis_value_tests::request(
            &mut client,
            &actual.iter().map(String::as_str).collect::<Vec<_>>(),
            b"-ERR no recorded Redis dependency matched\r\n",
        )
        .await;
        assert_eq!(
            crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap(),
            immutable
        );
        task.abort();
    }
}
