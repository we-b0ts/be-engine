//! Evidence-backed policy edits for captured identities and response header dates.
mod dependency_request;
mod mysql_time;
mod redis_time;
mod response_jwt;
use super::super::{
    config::fingerprint, dynamic_values::DynamicValueRule, response_headers::ResponseHeaderDateRule,
};
use super::response_body::ResponseBodyRuleEvidence;
use anyhow::{Result, ensure};
pub use dependency_request::{DependencyRequestRuleFeedback, plan_dependency_request_rule};
pub use mysql_time::DynamicValueMysqlTimeRule;
pub use redis_time::{DynamicValueRedisTimeRule, RedisJsonTimeValueSelector};
pub use response_jwt::{ResponseJwtRuleFeedback, plan_response_jwt_rule};
use serde::Serialize;
#[cfg(test)]
use std::fs;
use std::path::PathBuf;

#[cfg(test)]
mod tests;

pub struct DynamicValueRuleFeedback {
    pub policy_path: PathBuf,
    pub rule: DynamicValueRule,
    pub replay_report: PathBuf,
}

pub struct ResponseHeaderDateRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub rules: Vec<ResponseHeaderDateRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedValueRuleReport {
    pub kind: String,
    pub api: String,
    pub policy_fingerprint: String,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub added_rule_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub requires_fresh_replay: bool,
    pub diff: String,
}

pub struct GeneratedValueRulePlan {
    policy_path: PathBuf,
    original: String,
    witnesses: Vec<(PathBuf, String)>,
    report: GeneratedValueRuleReport,
}

impl GeneratedValueRulePlan {
    pub(crate) fn evidence_witnesses(&self) -> Vec<(PathBuf, String)> {
        std::iter::once((
            self.policy_path.clone(),
            fingerprint(self.original.as_bytes()),
        ))
        .chain(self.witnesses.iter().cloned())
        .collect()
    }

    pub(crate) fn ensure_evidence_current(witnesses: &[(PathBuf, String)]) -> Result<()> {
        ensure!(
            !witnesses.is_empty(),
            "pending generated-value plan has no frozen evidence"
        );
        for (path, identity) in witnesses {
            ensure!(
                fingerprint(&super::read_published_report(
                    path,
                    "generated value witness"
                )?) == *identity,
                "generated value evidence changed after planning"
            );
        }
        Ok(())
    }

    pub fn report(&self) -> &GeneratedValueRuleReport {
        &self.report
    }
    pub fn apply(self) -> Result<GeneratedValueRuleReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}

pub fn plan_dynamic_value_rule(
    _feedback: DynamicValueRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}

pub fn plan_dynamic_value_mysql_time_rule(
    _feedback: DynamicValueRuleFeedback,
    _time: DynamicValueMysqlTimeRule,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}

pub fn plan_dynamic_value_redis_time_rule(
    _feedback: DynamicValueRuleFeedback,
    _time: DynamicValueRedisTimeRule,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}
pub fn plan_response_header_date_rule(
    _feedback: ResponseHeaderDateRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}
