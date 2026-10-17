//! Explicit signed-token response contracts; secrets stay in startup inputs.
use super::*;
use crate::request_rules::JwtDynamicClaim;

mod input;
mod key_source;
pub use key_source::ResponseJwtKeySource;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseJwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
}

impl ResponseJwtAlgorithm {
    pub(in crate::replay) fn hmac(self) -> Option<crate::request_rules::JwtAlgorithm> {
        use crate::request_rules::JwtAlgorithm as A;
        match self {
            Self::HS256 => Some(A::HS256),
            Self::HS384 => Some(A::HS384),
            Self::HS512 => Some(A::HS512),
            Self::RS256 => None,
        }
    }
}

fn default_expiry_format() -> ResponseTimestampFormat {
    ResponseTimestampFormat::Rfc3339
}
fn is_default_expiry_format(format: &ResponseTimestampFormat) -> bool {
    *format == default_expiry_format()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseJwtRule {
    pub pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nonce_query_params: BTreeMap<String, String>,
    pub algorithm: ResponseJwtAlgorithm,
    pub signing_key_source: ResponseJwtKeySource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_claims: Vec<JwtDynamicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_query_param: Option<String>,
    /// RFC3339 response timestamp whose floored Unix seconds must equal JWT exp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(
        default = "default_expiry_format",
        skip_serializing_if = "is_default_expiry_format"
    )]
    pub expires_at_format: ResponseTimestampFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    pub source_evidence: String,
}

impl ResponseJwtRule {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.header.is_none() {
            validate_json_pointer(&self.pointer)?;
        }
        self.signing_key_source.validate(self.algorithm)?;
        ensure!(
            matches!(
                self.expires_at_format,
                ResponseTimestampFormat::Rfc3339 | ResponseTimestampFormat::UnixSeconds
            ),
            "JWT expires_at_format supports rfc3339 or unix_seconds"
        );
        ensure!(
            self.expires_at.is_some() || is_default_expiry_format(&self.expires_at_format),
            "JWT expires_at_format requires expires_at"
        );
        ensure!(
            self.ttl.is_none() || self.expires_at.is_some() && self.issued_at.is_some(),
            "JWT ttl requires expires_at and issued_at"
        );
        validate_audit_text(&self.source_evidence, "source_evidence", 512)?;
        let mut claims = BTreeSet::new();
        for claim in &self.dynamic_claims {
            claim.validate()?;
            ensure!(
                claims.insert(claim.pointer()),
                "JWT nonce claim is selected twice"
            );
        }
        let mut parameters = BTreeSet::new();
        for (claim, parameter) in &self.nonce_query_params {
            ensure!(
                claims.contains(claim.as_str()) && self.url_query_param.is_some(),
                "JWT query echo requires a declared nonce and URL query token"
            );
            ensure!(
                Some(parameter) != self.url_query_param.as_ref() && parameters.insert(parameter),
                "JWT query echoes must select distinct parameters"
            );
            crate::request_rules::jwt::url_query::validate_parameter(parameter)?;
        }
        if let Some(header) = &self.header {
            header.parse::<hyper::header::HeaderName>()?;
            ensure!(
                self.pointer.is_empty()
                    && self.companion_pointers().next().is_none()
                    && self.ttl.is_none(),
                "header JWT cannot own body pointers"
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
        for pointer in self
            .companion_pointers()
            .chain(self.ttl.iter().map(String::as_str))
        {
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

    pub(in crate::replay) fn companion_pointers(&self) -> impl Iterator<Item = &str> {
        self.expires_at
            .iter()
            .chain(&self.issued_at)
            .map(String::as_str)
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
