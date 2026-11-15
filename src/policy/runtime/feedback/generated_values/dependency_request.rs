//! Planning for bounded dependency request contracts with protected witnesses.
use super::*;
use serde_json::Value;

pub struct DependencyRequestRuleFeedback {
    pub policy_path: PathBuf,
    pub rule: Value,
    pub replay_report: PathBuf,
}

pub fn plan_dependency_request_rule(
    _feedback: DependencyRequestRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}
