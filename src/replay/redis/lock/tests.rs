use super::*;
use crate::replay::redis::{MatchedRedisExchange, RedisReplayState, TargetConnection, TargetKey};
use crate::replay::report::command::CommandMatchDiagnostic;
use serde_json::json;
use std::{fs, path::PathBuf};

fn selector() -> RedisLockSelector {
    RedisLockSelector {
        host: "redis.test".into(),
        port: 6379,
        key: RedisValueKeySelector::Affix {
            prefix: "lock:".into(),
            suffix: String::new(),
        },
    }
}
fn record(connection: uuid::Uuid, sequence: u64, command: &str, args: &[&str]) -> RecordedExchange {
    serde_json::from_value(json!({"connection_id":connection,"sequence":sequence,"target_host":"redis.test","target_port":6379,
        "resp_version":2,"database":0,"username":null,"command":command,
        "args":args.iter().map(|arg|json!({"encoding":"utf8","data":arg})).collect::<Vec<_>>(),
        "response_kind":if command=="SET" {"simple_string"} else {"integer"},
        "response":{"encoding":"utf8","data":if command=="SET" {"+OK\r\n"} else {":1\r\n"}},"replay_safe":true})).unwrap()
}
fn fixture(command: &str, source: ReplaySource) -> RedisReplayState {
    let mut state = RedisReplayState::default();
    let lane = uuid::Uuid::new_v4();
    let args = if command == "DELEX" {
        vec!["lock:1", "IFEQ", "source-secret-token"]
    } else {
        vec!["script-identity", "1", "lock:1", "source-secret-token"]
    };
    for r in [
        record(
            lane,
            1,
            "SET",
            &["lock:1", "source-secret-token", "PX", "30000", "NX"],
        ),
        record(lane, 2, command, &args),
    ] {
        state
            .register_exchange(
                r,
                source,
                if source == ReplaySource::Case {
                    Some("case")
                } else {
                    None
                },
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
    state
}
fn configure(state: &mut RedisReplayState) {
    state.configure_lock_tokens(&[LockTokenRule {
        id: "locks".into(),
        selector: selector(),
    }]);
}
fn request(
    state: &mut RedisReplayState,
    command: &str,
    args: &[&str],
) -> Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some("case"),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection {
            id: uuid::Uuid::nil(),
            bound: None,
        },
        2,
        0,
        None,
        command,
        &args
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
}
#[test]
fn one_rule_preserves_nonce_identity_across_all_release_forms_without_uuid_or_script_config() {
    for command in ["EVALSHA", "EVAL", "DELEX"] {
        let mut state = fixture(command, ReplaySource::Case);
        let set = ["lock:1", "target-random-token", "PX", "30000", "NX"];
        assert!(request(&mut state, "SET", &set).is_err());
        configure(&mut state);
        let early = if command == "DELEX" {
            vec!["lock:1", "IFEQ", "source-secret-token"]
        } else {
            vec!["script-identity", "1", "lock:1", "source-secret-token"]
        };
        assert!(request(&mut state, command, &early).is_err());
        let matched = request(&mut state, "SET", &set).unwrap();
        assert_eq!(matched.rule_ids, ["locks"]);
        state.complete_exchange(&matched);
        let wrong = if command == "DELEX" {
            vec!["lock:1", "IFEQ", "other-target-token"]
        } else {
            vec!["script-identity", "1", "lock:1", "other-target-token"]
        };
        assert!(request(&mut state, command, &wrong).is_err());
        let correct = if command == "DELEX" {
            vec!["lock:1", "IFEQ", "target-random-token"]
        } else {
            vec!["script-identity", "1", "lock:1", "target-random-token"]
        };
        let matched = request(&mut state, command, &correct).unwrap();
        assert_eq!(matched.response, b":1\r\n");
        state.complete_exchange(&matched);
        assert!(state.snapshot().unused_case.is_empty());
        assert!(request(&mut state, command, &correct).is_err());
    }
}
#[test]
fn key_expiry_options_script_session_and_case_remain_strict() {
    let mut state = fixture("EVALSHA", ReplaySource::Case);
    configure(&mut state);
    for bad in [
        ["other:1", "target", "PX", "30000", "NX"],
        ["lock:1", "target", "PX", "30001", "NX"],
        ["lock:1", "target", "EX", "30000", "NX"],
        ["lock:1", "target", "PX", "30000", "XX"],
        ["lock:1", "", "PX", "30000", "NX"],
    ] {
        assert!(request(&mut state, "SET", &bad).is_err());
    }
    let args = [
        b"lock:1".to_vec(),
        b"target".to_vec(),
        b"PX".to_vec(),
        b"30000".to_vec(),
        b"NX".to_vec(),
    ];
    for (case, host, port, db, user) in [
        (Some("other"), "redis.test", 6379, 0, None),
        (Some("case"), "redis.test", 6380, 0, None),
        (Some("case"), "other.test", 6379, 0, None),
        (Some("case"), "redis.test", 6379, 1, None),
        (Some("case"), "redis.test", 6379, 0, Some("other")),
    ] {
        assert!(
            state
                .match_redis(
                    case,
                    &TargetKey {
                        host: host.into(),
                        port
                    },
                    TargetConnection::default(),
                    2,
                    db,
                    user,
                    "SET",
                    &args
                )
                .is_err()
        );
    }
    let matched = request(
        &mut state,
        "SET",
        &["lock:1", "target", "PX", "30000", "NX"],
    )
    .unwrap();
    state.complete_exchange(&matched);
    assert!(
        request(
            &mut state,
            "EVALSHA",
            &["changed-script", "1", "lock:1", "target"]
        )
        .is_err()
    );
    assert!(
        request(
            &mut state,
            "EVALSHA",
            &["script-identity", "2", "lock:1", "target"]
        )
        .is_err()
    );
    let mut global = fixture("EVALSHA", ReplaySource::Global);
    configure(&mut global);
    assert!(
        request(
            &mut global,
            "SET",
            &["lock:1", "target", "PX", "30000", "NX"]
        )
        .is_err()
    );
}
#[test]
fn retries_preserve_equality_and_distinct_source_tokens_cannot_collapse() {
    let mut state = fixture("EVALSHA", ReplaySource::Case);
    let lane = state.exchanges[0].record.connection_id;
    for (seq, token) in [(3, "source-secret-token"), (4, "new-source-token")] {
        state
            .register_exchange(
                record(lane, seq, "SET", &["lock:1", token, "PX", "30000", "NX"]),
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
    }
    configure(&mut state);
    for (command, args) in [
        ("SET", vec!["lock:1", "target", "PX", "30000", "NX"]),
        ("EVALSHA", vec!["script-identity", "1", "lock:1", "target"]),
    ] {
        let m = request(&mut state, command, &args).unwrap();
        state.complete_exchange(&m);
    }
    assert!(
        request(
            &mut state,
            "SET",
            &["lock:1", "different", "PX", "30000", "NX"]
        )
        .is_err()
    );
    let m = request(
        &mut state,
        "SET",
        &["lock:1", "target", "PX", "30000", "NX"],
    )
    .unwrap();
    state.complete_exchange(&m);
    assert!(
        request(
            &mut state,
            "SET",
            &["lock:1", "target", "PX", "30000", "NX"]
        )
        .is_err()
    );
    assert!(request(&mut state, "SET", &["lock:1", "fresh", "PX", "30000", "NX"]).is_ok());
}
#[test]
fn shapes_support_option_orders_but_not_unconditional_or_multi_key_commands() {
    for args in [
        ["key", "token", "NX", "EX", "30"],
        ["key", "token", "PX", "30000", "NX"],
    ] {
        assert_eq!(
            positions("SET", &args.map(|s| s.as_bytes().to_vec())),
            Some((0, 1))
        );
    }
    assert!(positions("SET", &[b"key".to_vec(), b"token".to_vec()]).is_none());
    assert!(
        positions(
            "EVALSHA",
            &[
                b"sha".to_vec(),
                b"2".to_vec(),
                b"key".to_vec(),
                b"token".to_vec()
            ]
        )
        .is_none()
    );
}
fn plan_fixture() -> (tempfile::TempDir, crate::RedisLockFeedback, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let case = temp.path().join("apis/remove/case");
    fs::create_dir_all(&case).unwrap();
    let mut state = fixture("EVALSHA", ReplaySource::Case);
    let mut lines = String::new();
    for exchange in &state.exchanges {
        let mut value = serde_json::to_value(&exchange.record).unwrap();
        value["event_type"] = "redis_exchange".into();
        lines.push_str(&value.to_string());
        lines.push('\n');
    }
    let dependencies = case.join("dependencies.jsonl");
    fs::write(&dependencies, lines).unwrap();
    assert!(
        request(
            &mut state,
            "SET",
            &["lock:1", "target-private-token", "PX", "30000", "NX"]
        )
        .is_err()
    );
    let report = temp.path().join("replay.json");
    fs::write(
        &report,
        json!({"finalized":true,"redis":state.snapshot()}).to_string(),
    )
    .unwrap();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(&policy,"version: 3\nexpected_response: assertions_only\ndependency_rules: []\nresponse_rules: {json: {}}\n").unwrap();
    (
        temp,
        crate::RedisLockFeedback {
            policy_path: policy,
            case_source: case,
            replay_report_path: report,
            rule_id: "locks".into(),
            selector: selector(),
            source_evidence:
                "locks.rs:acquire/release uses random ownership tokens and compare-delete".into(),
        },
        dependencies,
    )
}
#[test]
fn source_lock_evidence_is_secret_free_stale_safe_and_authoring_is_retired() {
    let (_temp, feedback, dependencies) = plan_fixture();
    let candidates = evidence::discover(&feedback.replay_report_path).unwrap();
    let output = candidates.to_string();
    assert_eq!(candidates["candidates"].as_array().unwrap().len(), 1);
    assert!(!output.contains("source-secret-token") && !output.contains("target-private-token"));
    evidence::verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )
    .unwrap();
    let before = [
        fs::read(&dependencies).unwrap(),
        fs::read(&feedback.policy_path).unwrap(),
        fs::read(&feedback.replay_report_path).unwrap(),
    ];
    let error = crate::plan_redis_lock(feedback.clone()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("legacy rule authoring is retired")
    );
    assert_eq!(
        before,
        [
            fs::read(&dependencies).unwrap(),
            fs::read(&feedback.policy_path).unwrap(),
            fs::read(&feedback.replay_report_path).unwrap()
        ]
    );
    fs::write(
        &dependencies,
        String::from_utf8(before[0].clone())
            .unwrap()
            .replace("source-secret-token", "changed-source-token"),
    )
    .unwrap();
    assert!(
        evidence::verify(
            &feedback.case_source,
            &feedback.replay_report_path,
            &feedback.selector
        )
        .is_err()
    );
}
#[test]
fn unrelated_mismatches_and_missing_source_references_do_not_authorize_rules() {
    let (_temp, feedback, dependencies) = plan_fixture();
    let mut state = fixture("EVALSHA", ReplaySource::Case);
    assert!(request(&mut state, "SET", &["lock:1", "target", "PX", "999", "NX"]).is_err());
    assert!(
        serde_json::to_value(state.snapshot()).unwrap()["lock_tokens"]["candidates"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let first = fs::read_to_string(&dependencies)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    fs::write(&dependencies, first).unwrap();
    assert!(
        evidence::verify(
            &feedback.case_source,
            &feedback.replay_report_path,
            &feedback.selector
        )
        .is_err()
    );
    fs::write(
        &feedback.replay_report_path,
        r#"{"finalized":true,"redis":{}}"#,
    )
    .unwrap();
    assert_eq!(
        evidence::discover(&feedback.replay_report_path).unwrap()["requires_fresh_replay"],
        true
    );
    assert!(
        evidence::verify(
            &feedback.case_source,
            &feedback.replay_report_path,
            &feedback.selector
        )
        .is_err()
    );
}
#[test]
fn policy_requires_endpoint_source_proof_and_disjoint_selectors() {
    let rule = json!({"id":"locks","match":{"api":"GET /api", "resource":{"protocol":"redis","endpoint":"redis.test:6379"},
        "key":{"kind":"affix","prefix":"lock:"}},"effect":{"kind":"redis_lock"},
        "proof":{"source":"locks.rs:acquire/release","fact":"Source uses random ownership tokens and compare-delete"}});
    let parse = |rules: serde_json::Value| {
        crate::policy::parse_policy(
            &json!({"format":"traffic-policy/v2","rules":rules}).to_string(),
        )
    };
    parse(json!([rule])).unwrap();
    for (path, value) in [("endpoint", json!("redis.test:0")), ("endpoint", json!(""))] {
        let mut bad = rule.clone();
        bad["match"]["resource"][path] = value;
        assert!(parse(json!([bad])).is_err());
    }
    let mut missing_proof = rule.clone();
    missing_proof["proof"]["fact"] = json!("");
    assert!(parse(json!([missing_proof])).is_err());
    let mut duplicate = rule.clone();
    duplicate["id"] = "other".into();
    assert!(parse(json!([rule, duplicate])).is_err());
}

#[test]
fn source_lock_order_requires_completion_before_the_earliest_proven_reference_start() {
    let mut state = fixture("EVAL", ReplaySource::Case);
    let acquired: chrono::DateTime<chrono::Utc> = "2026-10-17T00:00:00Z".parse().unwrap();
    state.exchanges[0].record.timestamp = Some(acquired);
    state.exchanges[1].record.timestamp = Some(acquired + chrono::TimeDelta::milliseconds(2));
    state.exchanges[1].record.request_started_at = Some(acquired);
    let rules = [LockTokenRule {
        id: "locks".into(),
        selector: selector(),
    }];
    let scope = crate::replay::policy::request_contract::RequestContracts::default();
    assert_eq!(
        LockTokens::validate_source(&state.exchanges, &rules, &scope).unwrap()["locks"],
        2
    );
    state.exchanges[1].record.request_started_at =
        Some(acquired - chrono::TimeDelta::nanoseconds(1));
    assert!(LockTokens::validate_source(&state.exchanges, &rules, &scope).is_err());
    // A missing exact start may only use the conservative millisecond interval.
    state.exchanges[1].record.request_started_at = None;
    assert!(LockTokens::validate_source(&state.exchanges, &rules, &scope).is_ok());
    state.exchanges[1].record.timestamp = Some(acquired + chrono::TimeDelta::microseconds(500));
    assert!(LockTokens::validate_source(&state.exchanges, &rules, &scope).is_err());
    state.exchanges[0].record.timestamp = None;
    assert!(LockTokens::validate_source(&state.exchanges, &rules, &scope).is_err());
}
