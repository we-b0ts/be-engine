//! Historical cross-case plan DTOs retain the unified-authoring boundary.
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use traffic_protocol_redis::bindings::RedisSharedReadSelector;
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
    report: RedisCrossCaseReport,
}

impl RedisCrossCasePlan {
    pub fn report(&self) -> &RedisCrossCaseReport {
        &self.report
    }

    pub fn apply(self) -> Result<RedisCrossCaseReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}

pub fn plan_redis_cross_case(_feedback: RedisCrossCaseFeedback) -> Result<RedisCrossCasePlan> {
    Err(crate::policy::legacy_authoring_error())
}
