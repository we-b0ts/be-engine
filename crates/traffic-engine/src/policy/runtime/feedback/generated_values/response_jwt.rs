//! Legacy JWT response planner compatibility.
use super::*;
use crate::policy::runtime::ResponseJwtRule;
#[derive(Debug, Clone)]
pub struct ResponseJwtRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub rules: Vec<ResponseJwtRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

pub fn plan_response_jwt_rule(
    _feedback: ResponseJwtRuleFeedback,
) -> Result<GeneratedValueRulePlan> {
    Err(crate::policy::legacy_authoring_error())
}

#[cfg(test)]
mod tests;
