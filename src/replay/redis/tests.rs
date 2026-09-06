use super::*;
use crate::BackgroundDependencyRuleConfig;

mod client_info;
mod pooling_scope;

#[test]
fn cache_snapshot_seed_can_satisfy_repeated_logical_reads() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let rule = BackgroundDependencyRuleConfig::Redis {
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
                global_dependency_reason: Some("background_rule".to_string()),
            },
            ReplaySource::Global,
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
                global_dependency_reason: None,
            },
            ReplaySource::Global,
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
                global_dependency_reason: None,
            },
            ReplaySource::Global,
            None,
            &mut targets,
            &[],
        )
        .unwrap_err();

    assert!(error.to_string().contains("subject does not match"));
    assert!(targets.is_empty());
}

fn capture(data: &str) -> RecordedCapture {
    RecordedCapture {
        encoding: "utf8".to_string(),
        data: data.to_string(),
        truncated: false,
    }
}
