use crate::rewrite::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtPlanRecord {
    pub rule: JwtRule,
    pub profile: JwtProfile,
    pub policy_revision: String,
    pub evidence_revision: String,
    pub leeway_seconds: i64,
}
