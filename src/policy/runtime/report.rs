use serde::Serialize;

use super::config::{DependencyProtocol, ExpectedResponseUsage};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReplayPolicyReport {
    pub(crate) version: u8,
    pub(crate) path: String,
    pub(crate) fingerprint: String,
    pub(crate) expected_response: ExpectedResponseUsage,
    pub(crate) dependency_rules: Vec<DependencyRuleReport>,
    pub(crate) global_formats: Vec<GlobalFormatReport>,
    pub(crate) request_contract_candidates: Vec<super::request_contract::Candidate>,
    pub(crate) dynamic_bindings: Vec<super::dynamic_values::DynamicBindingReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) redis_read_backs: Vec<super::request_contract::RedisReadBackReport>,
    pub(crate) key_bindings: Vec<super::request_contract::KeyBindingReport>,
    pub(crate) dynamic_capture_candidates: Vec<super::dynamic_values::CaptureCandidate>,
    pub(crate) unused_applicable_dependency_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) recorded_mysql_rule_applicability: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<RecordedDependencyRuleSource>,
    >,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) recorded_redis_rule_applicability:
        std::collections::BTreeMap<String, std::collections::BTreeSet<RecordedRedisRuleSource>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecordedDependencyRuleSource {
    pub(crate) case_id: String,
    pub(crate) index: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecordedRedisRuleSource {
    pub(crate) case_id: String,
    pub(crate) connection_id: String,
    pub(crate) sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DependencyRuleReport {
    pub(crate) id: String,
    pub(crate) protocol: DependencyProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kind: Option<&'static str>,
    pub(crate) applicable: bool,
    pub(crate) matches: usize,
    pub(crate) binds: usize,
    pub(crate) references: usize,
    pub(crate) validations: usize,
    pub(crate) time_validations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GlobalFormatReport {
    pub(crate) id: String,
    pub(crate) applicable: bool,
    pub(crate) validations: usize,
    pub(crate) time_validations: usize,
}
