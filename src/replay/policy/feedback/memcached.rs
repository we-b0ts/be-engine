use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::config::edit::write_atomic;

use super::super::config::{
    MemcachedResourceSelector, MemcachedSelector, NumericKeySelector, PolicyProtocol,
    ProtobufSelector, ProtobufTimestampFieldRule, ProtobufTimestampMechanism, ReplayPolicyRule,
    TargetSelector, load_replay_policy,
};

#[derive(Debug, Clone)]
pub struct MemcachedTimestampRuleFeedback {
    pub policy_path: PathBuf,
    pub rule_id: String,
    pub port: u16,
    pub key_prefix: String,
    pub key_suffix: String,
    pub field_number: u32,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemcachedTimestampRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub requested_rule_id: String,
    pub effective_rule_id: String,
    pub resource_kind: &'static str,
    pub port: u16,
    pub command: &'static str,
    pub key_prefix: String,
    pub key_suffix: String,
    pub protobuf_field_number: u32,
    pub mechanism: &'static str,
    pub source_evidence: String,
    pub fixed_tolerance_seconds: u8,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct MemcachedTimestampRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    report: MemcachedTimestampRuleReport,
}

impl MemcachedTimestampRulePlan {
    pub fn report(&self) -> &MemcachedTimestampRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<MemcachedTimestampRuleReport> {
        let current = fs::read_to_string(&self.policy_path).with_context(|| {
            format!(
                "failed to reread replay policy {}",
                self.policy_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "replay policy changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_memcached_timestamp_rule(
    feedback: MemcachedTimestampRuleFeedback,
) -> Result<MemcachedTimestampRulePlan> {
    let original = fs::read_to_string(&feedback.policy_path).with_context(|| {
        format!(
            "failed to read replay policy {}",
            feedback.policy_path.display()
        )
    })?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let proposed = proposed_rule(&feedback);

    if let Some(existing) = loaded
        .document
        .rules
        .iter()
        .find(|rule| rule.id == feedback.rule_id)
    {
        ensure!(
            same_memcached_timestamp_selector(existing, &feedback),
            "replay policy rule id {:?} already selects a different dependency field",
            feedback.rule_id
        );
    }

    let reusable = loaded
        .document
        .rules
        .iter()
        .find(|rule| same_memcached_timestamp_selector(rule, &feedback))
        .map(|rule| rule.id.clone());
    let reused_existing = reusable.is_some();
    let effective_rule_id = reusable.unwrap_or_else(|| feedback.rule_id.clone());
    if !reused_existing {
        loaded.document.rules.push(proposed);
        loaded
            .document
            .rules
            .sort_by(|left, right| left.id.cmp(&right.id));
    }

    let updated = replace_dependency_rules(&original, &loaded.document.rules)?;
    let changed = updated != original;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_dependency_rules(&loaded.document.rules)?
                .lines()
                .map(|line| format!("+{line}\n"))
                .collect::<String>()
        )
    } else {
        String::new()
    };

    Ok(MemcachedTimestampRulePlan {
        policy_path: feedback.policy_path.clone(),
        original,
        updated,
        report: MemcachedTimestampRuleReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            requested_rule_id: feedback.rule_id,
            effective_rule_id,
            resource_kind: "cache_service",
            port: feedback.port,
            command: "set",
            key_prefix: feedback.key_prefix,
            key_suffix: feedback.key_suffix,
            protobuf_field_number: feedback.field_number,
            mechanism: "unix_seconds",
            source_evidence: feedback.source_evidence,
            fixed_tolerance_seconds: 5,
            reused_existing,
            changed,
            applied: false,
            diff,
        },
    })
}

fn proposed_rule(feedback: &MemcachedTimestampRuleFeedback) -> ReplayPolicyRule {
    ReplayPolicyRule {
        id: feedback.rule_id.clone(),
        case_selector: None,
        protocol: PolicyProtocol::Memcached,
        target: TargetSelector::default(),
        mysql: None,
        http: None,
        memcached: Some(MemcachedSelector {
            resource: MemcachedResourceSelector::CacheService {
                port: feedback.port,
            },
            command: "set".to_string(),
            key: NumericKeySelector {
                prefix: feedback.key_prefix.clone(),
                suffix: feedback.key_suffix.clone(),
            },
            protobuf: ProtobufSelector {
                timestamp_fields: BTreeMap::from([(
                    feedback.field_number,
                    ProtobufTimestampFieldRule {
                        mechanism: ProtobufTimestampMechanism::UnixSeconds,
                        source_evidence: feedback.source_evidence.clone(),
                    },
                )]),
            },
        }),
    }
}

fn same_memcached_timestamp_selector(
    rule: &ReplayPolicyRule,
    feedback: &MemcachedTimestampRuleFeedback,
) -> bool {
    if rule.protocol != PolicyProtocol::Memcached || rule.case_selector.is_some() {
        return false;
    }
    let Some(memcached) = &rule.memcached else {
        return false;
    };
    memcached.command == "set"
        && memcached.resource.port() == feedback.port
        && memcached.key.prefix == feedback.key_prefix
        && memcached.key.suffix == feedback.key_suffix
        && memcached
            .protobuf
            .timestamp_fields
            .contains_key(&feedback.field_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feedback(policy_path: PathBuf) -> MemcachedTimestampRuleFeedback {
        MemcachedTimestampRuleFeedback {
            policy_path,
            rule_id: "user-info-loading-time".to_string(),
            port: 15138,
            key_prefix: "u".to_string(),
            key_suffix: String::new(),
            field_number: 50,
            source_evidence: "CacheService.java:2044 sets loading_time from Unix seconds"
                .to_string(),
        }
    }

    #[test]
    fn plans_and_applies_a_minimal_cache_service_rule() {
        let temp = tempfile::tempdir().unwrap();
        let policy_path = temp.path().join("verification.yaml");
        fs::write(
            &policy_path,
            "version: 3\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();

        let plan = plan_memcached_timestamp_rule(feedback(policy_path.clone())).unwrap();
        assert_eq!(plan.report().fixed_tolerance_seconds, 5);
        assert_eq!(plan.report().resource_kind, "cache_service");
        assert_eq!(plan.report().port, 15138);
        assert!(plan.report().changed);
        assert!(plan.updated.contains("kind: cache_service"));
        assert!(plan.updated.contains("port: 15138"));
        assert!(plan.updated.contains("50:"));
        assert!(!plan.updated.contains("target: {}"));
        assert!(!plan.updated.contains("namespace:"));
        assert!(!plan.updated.contains("tolerance"));

        let report = plan.apply().unwrap();
        assert!(report.applied);
        let applied = fs::read_to_string(&policy_path).unwrap();
        assert!(applied.contains("user-info-loading-time"));
        super::super::super::config::load_replay_policy(&policy_path).unwrap();

        let reused = plan_memcached_timestamp_rule(feedback(policy_path)).unwrap();
        assert!(reused.report().reused_existing);
        assert!(!reused.report().changed);
    }
}
