//! Explicit signed-token response contracts; secrets stay in startup inputs.
use super::*;
use crate::request_rules::{JwtAlgorithm, keys::SigningKeySource};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseJwtRule {
    pub pointer: String,
    pub algorithm: JwtAlgorithm,
    pub signing_key_source: SigningKeySource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_claims: Vec<String>,
    pub source_evidence: String,
}

impl ResponseJwtRule {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_json_pointer(&self.pointer)?;
        crate::request_rules::keys::validate_source(&self.signing_key_source)?;
        validate_audit_text(&self.source_evidence, "source_evidence", 512)?;
        ensure!(
            self.dynamic_claims.is_empty() || self.dynamic_claims == ["/jti"],
            "JWT dynamic claims support only an explicit UUID v4 /jti"
        );
        Ok(())
    }

    pub(crate) fn id(&self, api: &str) -> String {
        response_rule_id(ResponseRuleKind::Jwt, api, &self.pointer)
    }
}
