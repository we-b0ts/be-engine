use super::*;
use crate::BackgroundDependencyRuleConfig;

mod client_info;
mod pooling_scope;
mod process_owned_publish;
mod process_owned_set;
mod termination;

#[test]
fn cache_snapshot_seed_can_satisfy_repeated_logical_reads() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let rule = BackgroundDependencyRuleConfig::Redis {
        key_sequence: Vec::new(),
        script: None,
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "snapshot-get".to_string(),
        ports: vec![6379],
        command: "GET".to_string(),
        keys: vec!["key".to_string()],
        key_patterns: Vec::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: Some(1_000),
        fields: Vec::new(),
        source_revision: "abcdef1".to_string(),
        source_evidence: "Cache.java:42".to_string(),
    };
    state
        .register_exchange(
            RecordedExchange {
                lifecycle_cleanup: false,
                native: NativeRecordedExchange {
                    parse_warnings: Vec::new(),
                    rpc_callback_capture: None,
                    id: None,
                    timestamp: None,
                    request_started_at: None,
                    connection_id: Uuid::new_v4(),
                    sequence: 1,
                    target_host: "redis.test".to_string(),
                    target_port: 6379,
                    resp_version: 2,
                    database: 0,
                    username: None,
                    command: "GET".to_string(),
                    args: vec![capture("key")],
                    response_kind: "bulk_string".to_string(),
                    response: capture("$2\r\nv1\r\n"),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: 1,
                    replay_safe: true,
                    cache_snapshot_rule: Some("snapshot-get".to_string()),
                    cache_snapshot_hit: false,
                    session_setup: false,
                    capture: Some(crate::dependency::observation::fixture_capture("process")),
                },
            },
            ReplaySource::Startup,
            None,
            &mut targets,
            std::slice::from_ref(&rule),
        )
        .unwrap();

    let target = TargetKey {
        host: "redis.test".to_string(),
        port: 6379,
    };
    for _ in 0..2 {
        let matched = state
            .match_redis(
                None,
                &target,
                TargetConnection::default(),
                2,
                0,
                None,
                "GET",
                &[b"key".to_vec()],
            )
            .unwrap();
        assert_eq!(matched.response, b"$2\r\nv1\r\n");
        state.complete_exchange(&matched);
    }

    let report = state.snapshot();
    assert_eq!(report.matched_count, 2);
    assert!(report.unused_global.is_empty());
}

#[test]
fn subscription_confirmation_registers_and_matches() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let connection_id = Uuid::new_v4();
    let response = "*3\r\n$10\r\npsubscribe\r\n$16\r\n/0.celery.pidbox\r\n:1\r\n";
    state
        .register_exchange(
            RecordedExchange {
                lifecycle_cleanup: false,
                native: NativeRecordedExchange {
                    parse_warnings: Vec::new(),
                    rpc_callback_capture: None,
                    id: None,
                    timestamp: None,
                    request_started_at: None,
                    connection_id,
                    sequence: 1,
                    target_host: "redis.test".to_string(),
                    target_port: 6379,
                    resp_version: 2,
                    database: 0,
                    username: None,
                    command: "PSUBSCRIBE".to_string(),
                    args: vec![capture("/0.celery.pidbox")],
                    response_kind: "array".to_string(),
                    response: capture(response),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: 1,
                    replay_safe: true,
                    cache_snapshot_rule: None,
                    cache_snapshot_hit: false,
                    session_setup: false,
                    capture: None,
                },
            },
            ReplaySource::Startup,
            None,
            &mut targets,
            &[],
        )
        .unwrap();

    let target = TargetKey {
        host: "redis.test".to_string(),
        port: 6379,
    };
    let matched = state
        .match_redis(
            None,
            &target,
            TargetConnection::default(),
            2,
            0,
            None,
            "PSUBSCRIBE",
            &[b"/0.celery.pidbox".to_vec()],
        )
        .unwrap();
    assert_eq!(matched.connection_id, connection_id);
    assert_eq!(matched.response, response.as_bytes());
    state.complete_exchange(&matched);
    assert!(state.snapshot().unused_global.is_empty());
}

#[test]
fn malformed_subscription_confirmation_is_rejected() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let error = state
        .register_exchange(
            RecordedExchange {
                lifecycle_cleanup: false,
                native: NativeRecordedExchange {
                    parse_warnings: Vec::new(),
                    rpc_callback_capture: None,
                    id: None,
                    timestamp: None,
                    request_started_at: None,
                    connection_id: Uuid::new_v4(),
                    sequence: 1,
                    target_host: "redis.test".to_string(),
                    target_port: 6379,
                    resp_version: 2,
                    database: 0,
                    username: None,
                    command: "SUBSCRIBE".to_string(),
                    args: vec![capture("events")],
                    response_kind: "array".to_string(),
                    response: capture("*3\r\n$9\r\nsubscribe\r\n$5\r\nother\r\n:1\r\n"),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: 1,
                    replay_safe: true,
                    cache_snapshot_rule: None,
                    cache_snapshot_hit: false,
                    session_setup: false,
                    capture: None,
                },
            },
            ReplaySource::Startup,
            None,
            &mut targets,
            &[],
        )
        .unwrap_err();

    assert!(error.to_string().contains("subject does not match"));
    assert!(targets.is_empty());
}

#[test]
fn malformed_or_unsupported_unsubscription_evidence_is_rejected_before_replay() {
    for (args, response_kind, response, resp_version) in [
        (
            vec!["events"],
            "array",
            "*3\r\n$11\r\nunsubscribe\r\n$5\r\nother\r\n:0\r\n",
            2,
        ),
        (
            vec!["events"],
            "array",
            "*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:-1\r\n",
            2,
        ),
        (vec!["events"], "simple_string", "+OK\r\n", 2),
        (vec!["events"], "error", "+OK\r\n", 2),
        (
            vec![],
            "array",
            "*3\r\n$11\r\nunsubscribe\r\n$-1\r\n:0\r\n",
            2,
        ),
        (vec!["events", "other"], "error", "-ERR denied\r\n", 2),
        (vec!["events"], "error", "-ERR denied\r\n", 3),
    ] {
        let mut state = RedisReplayState::default();
        let mut targets = BTreeMap::new();
        let record = unsubscription_record(&args, response_kind, response, resp_version);
        assert!(
            state
                .register_exchange(record, ReplaySource::Case, Some("case"), &mut targets, &[])
                .is_err()
        );
        assert!(targets.is_empty());
        assert!(state.exchanges.is_empty());
    }
}

#[test]
fn unsubscription_errors_and_nonzero_remaining_counts_preserve_recorded_responses() {
    for (kind, response) in [
        (
            "array",
            "*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:1\r\n",
        ),
        ("error", "-NOPERM permission denied\r\n"),
    ] {
        let mut state = RedisReplayState::default();
        state
            .register_exchange(
                unsubscription_record(&["events"], kind, response, 2),
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
        let matched = state
            .match_redis(
                Some("case"),
                &TargetKey {
                    host: "redis.test".to_string(),
                    port: 6379,
                },
                TargetConnection::default(),
                2,
                0,
                None,
                "UNSUBSCRIBE",
                &[b"events".to_vec()],
            )
            .unwrap();
        assert_eq!(matched.response, response.as_bytes());
        assert!(matched.requires_binding);
        state.complete_exchange(&matched);
        assert!(state.snapshot().unused_case.is_empty());
    }
}

fn unsubscription_record(
    args: &[&str],
    kind: &str,
    response: &str,
    resp_version: u8,
) -> RecordedExchange {
    serde_json::from_value(serde_json::json!({
        "connection_id":Uuid::new_v4(), "sequence":1, "target_host":"redis.test",
        "target_port":6379, "resp_version":resp_version, "database":0, "username":null,
        "command":"UNSUBSCRIBE", "args":args.iter().map(|arg| capture(arg)).collect::<Vec<_>>(),
        "response_kind":kind, "response":capture(response), "replay_safe":true,
    }))
    .unwrap()
}

fn capture(data: &str) -> RecordedCapture {
    RecordedCapture {
        encoding: "utf8".to_string(),
        data: data.to_string(),
        truncated: false,
    }
}
