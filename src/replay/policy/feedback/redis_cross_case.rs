//! Promote one already configured Redis shared-read rule to finite recording-run scope.
use super::document::{render_dependency_rules, replace_dependency_rules};
use crate::replay::policy::config::{
    DependencyProtocol, ReplayScope, load_replay_policy, validate_document,
};
use crate::replay::policy::redis_value::RedisSelector;
use crate::replay::redis::{cross_case, shared_read::RedisSharedReadSelector};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct RedisCrossCaseFeedback {
    pub policy_path: PathBuf,
    pub case_source: PathBuf,
    pub replay_report_path: PathBuf,
    pub rule_id: String,
    pub source_evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedisCrossCaseReport {
    pub policy_revision: String,
    pub policy: PathBuf,
    pub effective_rule_id: String,
    pub selector: RedisSharedReadSelector,
    pub source_evidence: String,
    pub evidence: serde_json::Value,
    pub reused_existing: bool,
    pub changed: bool,
    pub applied: bool,
    pub requires_replay: bool,
    pub diff: String,
}

pub struct RedisCrossCasePlan {
    feedback: RedisCrossCaseFeedback,
    original: String,
    updated: String,
    report: RedisCrossCaseReport,
}

impl RedisCrossCasePlan {
    pub fn report(&self) -> &RedisCrossCaseReport {
        &self.report
    }

    pub fn apply(self) -> Result<RedisCrossCaseReport> {
        crate::policy::retired_authoring()?;
        ensure!(
            fs::read_to_string(&self.feedback.policy_path)? == self.original,
            "policy changed after planning; rerun Redis cross-case plan"
        );
        let current = cross_case::verify_candidate(
            &self.feedback.case_source,
            &self.feedback.replay_report_path,
            &self.report.selector,
        )?;
        ensure!(
            current == self.report.evidence,
            "Redis cross-case evidence changed after planning"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.feedback.policy_path, self.updated.as_bytes())?;
        }
        Ok(RedisCrossCaseReport {
            applied: true,
            ..self.report
        })
    }
}

pub fn plan_redis_cross_case(feedback: RedisCrossCaseFeedback) -> Result<RedisCrossCasePlan> {
    crate::policy::retired_authoring()?;
    crate::config::process_owned_dependencies::validate_source_evidence(&feedback.source_evidence)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let loaded = load_replay_policy(&feedback.policy_path)?;
    let mut document = loaded.document.clone();
    let rule = document
        .dependency_rules
        .iter_mut()
        .find(|rule| rule.id == feedback.rule_id)
        .context("Redis cross-case requires an existing shared-read rule id")?;
    ensure!(
        rule.protocol == DependencyProtocol::Redis && rule.replay_scope == ReplayScope::Case,
        "Redis cross-case requires an existing case-scoped Redis shared-read rule"
    );
    let Some(RedisSelector::SharedRead(read)) = rule.redis.as_ref() else {
        anyhow::bail!("Redis cross-case requires an existing GET/HGET shared-read rule");
    };
    let selector = RedisSharedReadSelector {
        host: rule.target.host.clone(),
        port: rule.target.port,
        read: read.clone(),
    };
    rule.replay_scope = ReplayScope::RecordingRun;
    rule.source_evidence = feedback.source_evidence.clone();
    validate_document(&document)?;
    let evidence = cross_case::verify_candidate(
        &feedback.case_source,
        &feedback.replay_report_path,
        &selector,
    )?;
    let updated = replace_dependency_rules(&original, &document)?;
    let changed = original != updated;
    let diff = if changed {
        format!(
            "@@ dependency_rules @@\n{}",
            render_dependency_rules(&document)?
        )
    } else {
        String::new()
    };
    let report = RedisCrossCaseReport {
        policy_revision: format!("{:x}", Sha256::digest(original.as_bytes())),
        policy: feedback.policy_path.clone(),
        effective_rule_id: feedback.rule_id.clone(),
        selector,
        source_evidence: feedback.source_evidence.clone(),
        evidence,
        reused_existing: true,
        changed,
        applied: false,
        requires_replay: true,
        diff,
    };
    Ok(RedisCrossCasePlan {
        feedback,
        original,
        updated,
        report,
    })
}
