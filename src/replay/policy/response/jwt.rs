//! Explicit signed-token response contracts; secrets stay in startup inputs.
use super::*;
use crate::request_rules::{JwtAlgorithm, JwtDynamicClaim, keys::SigningKeySource};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseJwtRule {
    pub pointer: String,
    pub algorithm: JwtAlgorithm,
    pub signing_key_source: SigningKeySource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_claims: Vec<JwtDynamicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_query_param: Option<String>,
    /// RFC3339 response timestamp whose floored Unix seconds must equal JWT exp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub source_evidence: String,
}

impl ResponseJwtRule {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_json_pointer(&self.pointer)?;
        crate::request_rules::keys::validate_source(&self.signing_key_source)?;
        validate_audit_text(&self.source_evidence, "source_evidence", 512)?;
        let mut claims = BTreeSet::new();
        for claim in &self.dynamic_claims {
            claim.validate()?;
            ensure!(
                claims.insert(claim.pointer()),
                "JWT nonce claim is selected twice"
            );
        }
        if let Some(parameter) = &self.url_query_param {
            ensure!(
                !parameter.is_empty()
                    && parameter.len() <= 128
                    && parameter
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
                "JWT URL query selector must be a nonempty unreserved ASCII name"
            );
        }
        if let Some(pointer) = &self.expires_at {
            validate_json_pointer(pointer)?;
            let scope = |pointer: &str| {
                let parts = pointer.split('/').collect::<Vec<_>>();
                parts
                    .iter()
                    .rposition(|part| *part == "*")
                    .map(|index| parts[..=index].join("/"))
                    .unwrap_or_default()
            };
            ensure!(
                scope(pointer) == scope(&self.pointer),
                "JWT expiry and token selectors must share their array scope"
            );
        }
        Ok(())
    }

    /// Bind array indexes from either owned field to the same response item.
    pub(in crate::replay) fn concrete_pointer(pattern: &str, selected: &str) -> String {
        let selected = selected.split('/').collect::<Vec<_>>();
        pattern
            .split('/')
            .enumerate()
            .map(|(index, segment)| {
                if segment == "*" {
                    selected.get(index).copied().unwrap_or(segment)
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    pub(crate) fn id(&self, api: &str) -> String {
        response_rule_id(ResponseRuleKind::Jwt, api, &self.pointer)
    }
}
