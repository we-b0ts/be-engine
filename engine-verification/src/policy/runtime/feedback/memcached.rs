//! Historical Memcached planning DTOs and unified-authoring rejection.
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
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
    report: MemcachedTimestampRuleReport,
}

impl MemcachedTimestampRulePlan {
    pub fn report(&self) -> &MemcachedTimestampRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<MemcachedTimestampRuleReport> {
        Err(crate::policy::legacy_authoring_error())
    }
}

pub fn plan_memcached_timestamp_rule(
    _feedback: MemcachedTimestampRuleFeedback,
) -> Result<MemcachedTimestampRulePlan> {
    Err(crate::policy::legacy_authoring_error())
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
    fn retired_memcached_timestamp_planner_cannot_create_a_parallel_policy() {
        let fixture = super::super::tests::RetiredFixture::new();
        fixture.check(|| plan_memcached_timestamp_rule(feedback(fixture.policy.clone())));
    }
}
