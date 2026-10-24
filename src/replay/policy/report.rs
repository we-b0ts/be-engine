use serde::Serialize;

use super::config::{DependencyProtocol, ExpectedResponseUsage};

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ReplayPolicyReport {
    pub(in crate::replay) version: u8,
    pub(in crate::replay) path: String,
    pub(in crate::replay) fingerprint: String,
    pub(in crate::replay) expected_response: ExpectedResponseUsage,
    pub(in crate::replay) dependency_rules: Vec<DependencyRuleReport>,
    pub(in crate::replay) global_formats: Vec<GlobalFormatReport>,
    pub(in crate::replay) request_contract_candidates: Vec<super::request_contract::Candidate>,
    pub(in crate::replay) dynamic_bindings: Vec<super::dynamic_values::DynamicBindingReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) redis_read_backs: Vec<super::request_contract::RedisReadBackReport>,
    pub(in crate::replay) key_bindings: Vec<super::request_contract::KeyBindingReport>,
    pub(in crate::replay) dynamic_capture_candidates: Vec<super::dynamic_values::CaptureCandidate>,
    pub(in crate::replay) unused_applicable_dependency_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(in crate::replay) recorded_mysql_rule_applicability: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<RecordedDependencyRuleSource>,
    >,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(in crate::replay) recorded_redis_rule_applicability:
        std::collections::BTreeMap<String, std::collections::BTreeSet<RecordedRedisRuleSource>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::replay) struct RecordedDependencyRuleSource {
    pub(in crate::replay) case_id: String,
    pub(in crate::replay) index: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::replay) struct RecordedRedisRuleSource {
    pub(in crate::replay) case_id: String,
    pub(in crate::replay) connection_id: String,
    pub(in crate::replay) sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct DependencyRuleReport {
    pub(in crate::replay) id: String,
    pub(in crate::replay) protocol: DependencyProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) kind: Option<&'static str>,
    pub(in crate::replay) applicable: bool,
    pub(in crate::replay) matches: usize,
    pub(in crate::replay) binds: usize,
    pub(in crate::replay) references: usize,
    pub(in crate::replay) validations: usize,
    pub(in crate::replay) time_validations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct GlobalFormatReport {
    pub(in crate::replay) id: String,
    pub(in crate::replay) applicable: bool,
    pub(in crate::replay) validations: usize,
    pub(in crate::replay) time_validations: usize,
}
