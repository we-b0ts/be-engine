//! Evidence-gated policy authoring for Redis dependency request array ordering.
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::replay::RedisUnorderedSelector;
use crate::replay::policy::config::{
    DependencyProtocol, ReplayDependencyRule, ReplayScope, TargetSelector, load_replay_policy,
    validate_document,
};
use crate::replay::policy::redis_value::{RedisFieldRule, RedisSelector, RedisValueSelector};
use crate::replay::redis::value as redis_unordered;
use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct RedisUnorderedFeedback {
    pub policy_path: PathBuf,
    pub case_source: PathBuf,
    pub replay_report_path: PathBuf,
    pub rule_id: String,
    pub selector: RedisUnorderedSelector,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisUnorderedReport {
    pub policy_revision: String,
    pub policy: PathBuf,
    pub effective_rule_id: String,
    pub selector: RedisUnorderedSelector,
    pub source_evidence: String,
    pub candidates: serde_json::Value,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub requires_replay: bool,
    pub diff: String,
}

pub struct RedisUnorderedPlan {
    feedback: RedisUnorderedFeedback,
    original: String,
    updated: String,
    report: RedisUnorderedReport,
}

impl RedisUnorderedPlan {
    pub fn report(&self) -> &RedisUnorderedReport {
        &self.report
    }
    pub fn apply(self) -> Result<RedisUnorderedReport> {
        ensure!(
            fs::read_to_string(&self.feedback.policy_path)? == self.original,
            "policy changed after planning; rerun Redis unordered plan"
        );
        let current = redis_unordered::evidence::verify(
            &self.feedback.case_source,
            &self.feedback.replay_report_path,
            &self.feedback.selector,
        )?;
        ensure!(
            current == self.report.candidates,
            "Redis unordered evidence changed after planning"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.feedback.policy_path, self.updated.as_bytes())?;
        }
        Ok(RedisUnorderedReport {
            applied: true,
            ..self.report
        })
    }
}

pub fn plan_redis_unordered(feedback: RedisUnorderedFeedback) -> Result<RedisUnorderedPlan> {
    feedback.selector.validate()?;
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let proposed = ReplayDependencyRule {
        id: feedback.rule_id.clone(),
        replay_scope: ReplayScope::Case,
        source_evidence: String::new(),
        case_selector: None,
        protocol: DependencyProtocol::Redis,
        target: TargetSelector {
            host: Some(feedback.selector.host.clone()),
            port: Some(feedback.selector.port),
        },
        http: None,
        redis: Some(RedisSelector::Value(RedisValueSelector {
            key: feedback.selector.key.clone(),
            unordered: vec![RedisFieldRule {
                field: feedback.selector.field.clone(),
                source_evidence: feedback.source_evidence.clone(),
            }],
        })),
        mysql: None,
        memcached: None,
    };
    let mut document = loaded.document.clone();
    document.dependency_rules = vec![proposed.clone()];
    validate_document(&document)?;
    let candidates = redis_unordered::evidence::verify(
        &feedback.case_source,
        &feedback.replay_report_path,
        &feedback.selector,
    )?;
    let existing = loaded.document.dependency_rules.iter().find(|r| {
        r.replay_scope == ReplayScope::Case
            && r.target
                .host
                .as_ref()
                .is_some_and(|h| h.eq_ignore_ascii_case(&feedback.selector.host))
            && r.target.port == Some(feedback.selector.port)
            && r.redis.as_ref().is_some_and(|redis| {
                let RedisSelector::Value(redis) = redis else {
                    return false;
                };
                redis.key == feedback.selector.key
                    && redis
                        .unordered
                        .iter()
                        .any(|f| f.field == feedback.selector.field)
            })
    });
    let reused_existing = existing.is_some();
    let effective_rule_id = existing
        .map(|r| r.id.clone())
        .unwrap_or_else(|| feedback.rule_id.clone());
    ensure!(
        loaded
            .document
            .dependency_rules
            .iter()
            .all(|r| r.id != feedback.rule_id || r.id == effective_rule_id && reused_existing),
        "Redis unordered rule id already selects another rule"
    );
    if !reused_existing {
        loaded.document.dependency_rules.push(proposed);
    }
    validate_document(&loaded.document)?;
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    let changed = original != updated;
    let diff = if changed {
        format!(
            "@@ dependency_rules @@\n{}",
            render_dependency_rules(&loaded.document)?
        )
    } else {
        String::new()
    };
    let report = RedisUnorderedReport {
        policy_revision: format!("{:x}", Sha256::digest(original.as_bytes())),
        policy: feedback.policy_path.clone(),
        effective_rule_id,
        selector: feedback.selector.clone(),
        source_evidence: feedback.source_evidence.clone(),
        candidates,
        reused_existing,
        changed,
        applied: false,
        requires_replay: true,
        diff,
    };
    Ok(RedisUnorderedPlan {
        feedback,
        original,
        updated,
        report,
    })
}
