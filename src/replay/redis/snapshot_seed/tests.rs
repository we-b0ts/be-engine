use std::collections::BTreeMap;
use std::path::Path;

use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::*;
use crate::config::SourceTrafficPolicyConfig;
use crate::replay::redis::{RedisReplayState, TargetConnection};
use crate::replay::{ReplaySource, TargetKey};

fn policy(revision: &str) -> String {
    let revision = format!("sha256:{:x}", Sha256::digest(revision.as_bytes()));
    format!(
        "format: traffic-policy/v2
source_revision: {revision}
process_dependencies:
  tasks:
    recover_inbox:
      requests:
        - redis:
            ports: [6379]
            operation: HSCAN
            keys: [{{kind: numeric, prefix: 'inbox:', suffix: ''}}]
"
    )
}

fn rule(revision: &str) -> BackgroundDependencyRuleConfig {
    SourceTrafficPolicyConfig::parse(&policy(revision), Path::new("policy.yaml"))
        .unwrap()
        .process_owned_dependencies
        .remove(0)
}

fn legacy_rule(revision: &str) -> BackgroundDependencyRuleConfig {
    let native = crate::policy::parse_and_compile_policy(&policy(revision))
        .unwrap()
        .native
        .remove(0)
        .rule;
    let digest = Sha256::digest(
        serde_json::to_vec(&("process_dependencies", native.selector, native.effect)).unwrap(),
    );
    let mut legacy = rule(revision);
    let BackgroundDependencyRuleConfig::Redis { name, .. } = &mut legacy else {
        unreachable!()
    };
    *name = format!("dependency.process_dependencies.{digest:x}");
    legacy
}

fn seed(name: &str) -> RecordedExchange {
    serde_json::from_value(json!({
        "connection_id": Uuid::new_v4(), "sequence": 1,
        "target_host": "redis.test", "target_port": 6379,
        "resp_version": 2, "database": 0, "username": null,
        "command": "HSCAN",
        "args": [
            {"encoding": "utf8", "data": "inbox:123", "truncated": false},
            {"encoding": "utf8", "data": "0", "truncated": false}
        ],
        "response_kind": "array",
        "response": {"encoding": "utf8", "data": "*2\r\n$1\r\n0\r\n*0\r\n", "truncated": false},
        "replay_safe": true, "cache_snapshot_rule": name,
        "global_dependency_reason": "background_rule"
    }))
    .unwrap()
}

#[test]
fn source_upgrade_keeps_generated_snapshot_reusable_and_overlay_consistent() {
    let previous = legacy_rule("source-v1");
    let current = rule("source-v2");
    assert_ne!(previous.name(), current.name());
    assert_eq!(rule("source-v1").name(), current.name());
    let mut state = RedisReplayState::default();
    state
        .register_exchange(
            seed(previous.name()),
            ReplaySource::Global,
            None,
            &mut BTreeMap::new(),
            std::slice::from_ref(&current),
        )
        .unwrap();
    state.apply_snapshot_overlays(Path::new("/recording"), &[current]);
    assert!(state.snapshot_overlay_warnings.is_empty());
    assert_eq!(state.snapshot_overlays.len(), 1);
    assert_eq!(state.snapshot_overlays[0].derived_seeds, 0);
    assert_eq!(state.snapshot_overlays[0].reusable_seeds, 1);
    assert_eq!(
        state.exchanges[0].record.cache_snapshot_rule.as_deref(),
        Some(previous.name())
    );
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    for _ in 0..3 {
        let matched = state
            .match_redis(
                None,
                &target,
                TargetConnection::default(),
                2,
                0,
                None,
                "HSCAN",
                &[b"inbox:123".to_vec(), b"0".to_vec()],
            )
            .unwrap();
        assert_eq!(matched.response, b"*2\r\n$1\r\n0\r\n*0\r\n");
        state.complete_exchange(&matched);
    }
    assert_eq!(state.snapshot().matched_count, 3);
    assert!(state.snapshot().unused_global.is_empty());
}

#[test]
fn generated_name_does_not_waive_current_scope_or_seed_safety() {
    let previous = legacy_rule("source-v1");
    let current = rule("source-v2");
    let args = vec![b"inbox:123".to_vec(), b"0".to_vec()];
    let original = seed(previous.name());
    assert!(validate(&original, ReplaySource::Global, &[], &args).is_err());
    for (port, command, key) in [
        (6380, "HSCAN", "inbox:123"),
        (6379, "GET", "inbox:123"),
        (6379, "HSCAN", "inbox:abc"),
        (6379, "HSCAN", "another:123"),
    ] {
        let mut changed = original.clone();
        changed.target_port = port;
        changed.command = command.into();
        let changed_args = vec![key.as_bytes().to_vec(), b"0".to_vec()];
        assert!(
            validate(
                &changed,
                ReplaySource::Global,
                std::slice::from_ref(&current),
                &changed_args
            )
            .is_err()
        );
    }
    for invalid in ["hit", "error", "ownership"] {
        let mut changed = original.clone();
        match invalid {
            "hit" => changed.cache_snapshot_hit = true,
            "error" => changed.response_kind = "error".into(),
            "ownership" => changed.global_dependency_reason = Some("bootstrap_window".into()),
            _ => unreachable!(),
        }
        assert!(
            validate(
                &changed,
                ReplaySource::Global,
                std::slice::from_ref(&current),
                &args
            )
            .is_err()
        );
    }
    assert!(validate(&original, ReplaySource::Case, &[current], &args).is_err());
}

#[test]
fn explicit_names_and_malformed_generated_names_retain_exact_matching() {
    let generated = rule("source-v1");
    for name in [
        "another-rule",
        "dependency.process_dependencies.short",
        "dependency.localcache.0123456789",
    ] {
        assert!(!owner_name_matches(name, generated.name()));
        assert!(owner_name_matches(name, name));
    }
    assert!(!owner_name_matches(generated.name(), "explicit-rule"));
    let mut current = generated;
    let BackgroundDependencyRuleConfig::Redis { name, fields, .. } = &mut current else {
        unreachable!()
    };
    *name = "explicit-rule".into();
    *fields = vec!["1".into()];
    assert!(
        validate(
            &seed("explicit-rule"),
            ReplaySource::Global,
            &[current],
            &[b"inbox:123".to_vec(), b"0".to_vec()]
        )
        .is_err()
    );
}
