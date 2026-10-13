use std::collections::BTreeMap;
use std::fs;

use serde_json::json;

use super::*;
use crate::config::RedisKeyPatternConfig;
use crate::replay::TargetKey;
use crate::replay::redis::RecordedCapture;

fn rule() -> BackgroundDependencyRuleConfig {
    BackgroundDependencyRuleConfig::Redis {
        key_sequence: Vec::new(),
        script: None,
        trigger_source: None,
        key_templates: Vec::new(),
        arguments: Vec::new(),
        name: "big-list-version".to_string(),
        ports: vec![50_600],
        command: "HGET".to_string(),
        keys: vec!["big-list".to_string()],
        key_patterns: Vec::<RedisKeyPatternConfig>::new(),
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: vec!["version".to_string()],
        source_revision: "abcdef1".to_string(),
        source_evidence: "CacheLoader.java:42".to_string(),
    }
}

fn capture(data: &str) -> RecordedCapture {
    RecordedCapture {
        encoding: "utf8".to_string(),
        data: data.to_string(),
        truncated: false,
    }
}

fn record(reason: Option<&str>, response: &str) -> RecordedExchange {
    RecordedExchange {
        timestamp: None,
        connection_id: Uuid::new_v4(),
        sequence: 1,
        target_host: "redis.example".to_string(),
        target_port: 50_600,
        resp_version: 2,
        database: 0,
        username: None,
        command: "HGET".to_string(),
        args: vec![capture("big-list"), capture("version")],
        response_kind: "bulk_string".to_string(),
        response: capture(response),
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: false,
        global_dependency_reason: reason.map(str::to_string),
    }
}

#[test]
fn derives_one_reusable_seed_from_consistent_old_global_and_case_evidence() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let rule = rule();
    state
        .register_exchange(
            record(Some("bootstrap_window"), "$2\r\nv1\r\n"),
            ReplaySource::Global,
            None,
            &mut targets,
            std::slice::from_ref(&rule),
        )
        .unwrap();
    state
        .register_exchange(
            record(None, "$2\r\nv1\r\n"),
            ReplaySource::Case,
            Some("case-a"),
            &mut targets,
            std::slice::from_ref(&rule),
        )
        .unwrap();

    state.apply_snapshot_overlays(std::path::Path::new("/recording"), &[rule]);

    assert_eq!(state.snapshot_overlays.len(), 1);
    assert_eq!(state.snapshot_overlays[0].derived_seeds, 1);
    let target = TargetKey {
        host: "redis.example".to_string(),
        port: 50_600,
    };
    for _ in 0..3 {
        let matched = state
            .match_redis(
                Some("case-a"),
                &target,
                super::super::TargetConnection::default(),
                2,
                0,
                None,
                "HGET",
                &[b"big-list".to_vec(), b"version".to_vec()],
            )
            .unwrap();
        assert_eq!(matched.response, b"$2\r\nv1\r\n");
        state.complete_exchange(&matched);
    }
}

#[test]
fn conflicting_case_response_rejects_the_entire_rule_overlay() {
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let rule = rule();
    state
        .register_exchange(
            record(Some("bootstrap_window"), "$2\r\nv1\r\n"),
            ReplaySource::Global,
            None,
            &mut targets,
            std::slice::from_ref(&rule),
        )
        .unwrap();
    state
        .register_exchange(
            record(None, "$2\r\nv2\r\n"),
            ReplaySource::Case,
            Some("case-a"),
            &mut targets,
            std::slice::from_ref(&rule),
        )
        .unwrap();

    state.apply_snapshot_overlays(std::path::Path::new("/recording"), &[rule]);

    assert!(state.snapshot_overlays.is_empty());
    assert_eq!(state.snapshot_overlay_warnings.len(), 1);
    assert!(state.snapshot_overlay_warnings[0].contains("conflicting responses"));
    assert!(
        state
            .exchanges
            .iter()
            .all(|exchange| !exchange.reusable_snapshot)
    );
}

#[test]
fn failed_response_is_not_eligible_for_derivation() {
    let rule = rule();
    let mut failed = evidence_from_record(
        None,
        ReplaySource::Global,
        record(Some("bootstrap_window"), "-ERR unavailable\r\n"),
    )
    .unwrap();
    failed.response_kind = "error".to_string();

    let error = analyze_snapshot_evidence("/recording", &rule, &[failed]).unwrap_err();

    assert!(error.to_string().contains("failed or error response"));
}

#[test]
fn overlay_fingerprint_is_bound_to_the_case_source_and_current_rule() {
    let rule = rule();
    let evidence = vec![
        evidence_from_record(
            None,
            ReplaySource::Global,
            record(Some("bootstrap_window"), "$2\r\nv1\r\n"),
        )
        .unwrap(),
        evidence_from_record(None, ReplaySource::Case, record(None, "$2\r\nv1\r\n")).unwrap(),
    ];
    let first = analyze_snapshot_evidence("/recording-a", &rule, &evidence)
        .unwrap()
        .report
        .evidence_fingerprint;
    let moved = analyze_snapshot_evidence("/recording-b", &rule, &evidence)
        .unwrap()
        .report
        .evidence_fingerprint;
    let mut changed_rule = rule;
    let BackgroundDependencyRuleConfig::Redis {
        source_evidence, ..
    } = &mut changed_rule
    else {
        unreachable!()
    };
    *source_evidence = "CacheLoader.java:84".to_string();
    let changed = analyze_snapshot_evidence("/recording-a", &changed_rule, &evidence)
        .unwrap()
        .report
        .evidence_fingerprint;

    assert_ne!(first, moved);
    assert_ne!(first, changed);
}

#[test]
fn file_inspection_derives_without_modifying_immutable_recording() {
    let temp = tempfile::tempdir().unwrap();
    let recording = temp.path().join("recording");
    let case = recording.join("case-a");
    fs::create_dir_all(&case).unwrap();
    fs::write(
        case.join("request.json"),
        serde_json::to_vec(&json!({"method": "GET", "uri": "/case-a"})).unwrap(),
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}").unwrap();
    let global = recording.join("global-dependencies.jsonl");
    let case_dependencies = case.join("dependencies.jsonl");
    fs::write(
        &global,
        format!(
            "{}\n",
            record_json(Some("bootstrap_window"), "$2\r\nv1\r\n")
        ),
    )
    .unwrap();
    fs::write(
        &case_dependencies,
        format!("{}\n", record_json(None, "$2\r\nv1\r\n")),
    )
    .unwrap();
    let policy_path = temp.path().join("source-traffic-policy.yaml");
    let mut policy = SourceTrafficPolicyConfig::empty();
    policy.process_owned_dependencies.push(rule());
    fs::write(&policy_path, policy.render().unwrap()).unwrap();
    let global_before = fs::read(&global).unwrap();
    let case_before = fs::read(&case_dependencies).unwrap();

    let report =
        inspect_case_source_snapshot_overlay(&recording, &policy_path, "big-list-version").unwrap();

    assert_eq!(report.derived_seeds, 1);
    assert_eq!(report.matching_global_exchanges, 1);
    assert_eq!(report.matching_case_exchanges, 1);
    assert_eq!(fs::read(&global).unwrap(), global_before);
    assert_eq!(fs::read(&case_dependencies).unwrap(), case_before);
}

fn record_json(reason: Option<&str>, response: &str) -> serde_json::Value {
    let mut value = json!({
        "event_type": "redis_exchange",
        "connection_id": Uuid::new_v4(),
        "sequence": 1,
        "target_host": "redis.example",
        "target_port": 50_600,
        "resp_version": 2,
        "database": 0,
        "username": null,
        "command": "HGET",
        "args": [
            {"encoding": "utf8", "data": "big-list", "truncated": false},
            {"encoding": "utf8", "data": "version", "truncated": false}
        ],
        "response_kind": "bulk_string",
        "response": {"encoding": "utf8", "data": response, "truncated": false},
        "outcome": "response",
        "duration_ms": 1,
        "replay_safe": true,
        "cache_snapshot_hit": false,
        "session_setup": false
    });
    if let Some(reason) = reason {
        value["global_dependency_reason"] = json!(reason);
    }
    value
}
