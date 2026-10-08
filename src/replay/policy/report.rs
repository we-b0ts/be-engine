use serde::Serialize;

use super::config::{DependencyProtocol, ExpectedResponseUsage};

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct ReplayPolicyReport {
    pub(in crate::replay) version: u8,
    pub(in crate::replay) path: String,
    pub(in crate::replay) fingerprint: String,
    pub(in crate::replay) expected_response: ExpectedResponseUsage,
    pub(in crate::replay) dependency_rules: Vec<DependencyRuleReport>,
    pub(in crate::replay) dynamic_bindings: Vec<super::dynamic_values::DynamicBindingReport>,
    pub(in crate::replay) dynamic_capture_candidates: Vec<super::dynamic_values::CaptureCandidate>,
    pub(in crate::replay) unused_applicable_dependency_rule_ids: Vec<String>,
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
