use serde::Serialize;

use super::config::{DependencyProtocol, ExpectedResponseUsage};

#[derive(Debug, Clone, Serialize)]
pub struct ReplayPolicyReport {
    pub version: u8,
    pub path: String,
    pub fingerprint: String,
    pub expected_response: ExpectedResponseUsage,
    pub dependency_rules: Vec<DependencyRuleReport>,
    pub global_formats: Vec<GlobalFormatReport>,
    pub request_contract_candidates: Vec<super::request_contract::Candidate>,
    pub dynamic_bindings: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redis_read_backs: Vec<serde_json::Value>,
    pub key_bindings: Vec<super::request_contract::KeyBindingReport>,
    pub dynamic_capture_candidates: Vec<serde_json::Value>,
    pub unused_applicable_dependency_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub recorded_mysql_rule_applicability: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<RecordedDependencyRuleSource>,
    >,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub recorded_redis_rule_applicability:
        std::collections::BTreeMap<String, std::collections::BTreeSet<RecordedRedisRuleSource>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordedDependencyRuleSource {
    pub case_id: String,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordedRedisRuleSource {
    pub case_id: String,
    pub connection_id: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyRuleReport {
    pub id: String,
    pub protocol: DependencyProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub applicable: bool,
    pub matches: usize,
    pub binds: usize,
    pub references: usize,
    pub validations: usize,
    pub time_validations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlobalFormatReport {
    pub id: String,
    pub applicable: bool,
    pub validations: usize,
    pub time_validations: usize,
}
