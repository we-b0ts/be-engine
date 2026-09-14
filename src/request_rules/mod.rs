//! Explicit, engine-owned transformations of recorded inbound requests.
//! Never consumes assertion or dependency response values.

pub(crate) mod jwt;
pub mod keys;
pub use jwt::Algorithm as JwtAlgorithm;
pub(crate) mod policy;

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt: Vec<JwtRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    pub algorithm: jwt::Algorithm,
    pub time: JwtTime,
    pub signing_key_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwtTokenLocation {
    BearerHeader { header: String },
    QueryParameter { query_param: String },
}

impl JwtTokenLocation {
    fn selector_key(&self) -> (&'static str, &str) {
        match self {
            Self::BearerHeader { header } => ("header", header),
            Self::QueryParameter { query_param } => ("query_param", query_param),
        }
    }
}

impl JwtRule {
    pub(crate) fn location(&self) -> Result<JwtTokenLocation> {
        match (&self.header, &self.scheme, &self.query_param) {
            (Some(header), Some(scheme), None) => {
                ensure!(
                    scheme == "bearer",
                    "JWT header rules currently support the bearer scheme"
                );
                ensure!(
                    hyper::header::HeaderName::from_bytes(header.as_bytes()).is_ok(),
                    "invalid JWT header name"
                );
                ensure!(
                    header == &header.to_ascii_lowercase(),
                    "JWT header must be lowercase"
                );
                Ok(JwtTokenLocation::BearerHeader {
                    header: header.clone(),
                })
            }
            (None, None, Some(query_param)) => {
                ensure!(
                    !query_param.is_empty()
                        && query_param.len() <= 128
                        && query_param.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'-' | b'.' | b'_' | b'~')
                        }),
                    "JWT query parameter name must be 1-128 URL-unreserved ASCII bytes"
                );
                Ok(JwtTokenLocation::QueryParameter {
                    query_param: query_param.clone(),
                })
            }
            _ => anyhow::bail!("JWT rule must select exactly one bearer header or one query_param"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtTime {
    PreserveRelative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestRuleObservation {
    pub rule_id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_seconds: Option<i64>,
}

impl RequestRules {
    pub fn is_empty(&self) -> bool {
        self.jwt.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.jwt.len() <= 32,
            "at most 32 JWT request rules are supported"
        );
        let mut ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for rule in &self.jwt {
            keys::validate_reference(&rule.id)?;
            keys::validate_reference(&rule.signing_key_ref)?;
            ensure!(ids.insert(&rule.id), "duplicate JWT request rule id");
            let location = rule.location()?;
            let (location_kind, location_name) = location.selector_key();
            ensure!(
                selectors.insert((
                    location_kind.to_string(),
                    location_name.to_string(),
                    rule.algorithm,
                    rule.signing_key_ref.clone()
                )),
                "duplicate JWT request selector and key"
            );
        }
        Ok(())
    }
}

pub(crate) struct RequestRuleRuntime {
    rules: Vec<(JwtRule, Vec<u8>)>,
}

impl RequestRuleRuntime {
    pub(crate) fn load(target_root: &Path, policy: &Path) -> Result<Self> {
        let rules = policy::load(policy)?;
        let mut resolved = Vec::new();
        for rule in rules.jwt {
            let key = keys::resolve_binding(target_root, &rule.signing_key_ref)?;
            resolved.push((rule, key));
        }
        Ok(Self { rules: resolved })
    }

    pub(crate) fn apply(
        &self,
        request: &mut Value,
        now: DateTime<Utc>,
    ) -> Result<Vec<RequestRuleObservation>> {
        let mut observations = Vec::new();
        let mut transformed = BTreeSet::new();
        for (rule, key) in &self.rules {
            let location = rule.location()?;
            if transformed.contains(&location) {
                continue;
            }
            let Some(token) = jwt::request_token(request, &location)? else {
                continue;
            };
            let Some(token) = jwt::Token::parse(&token)? else {
                continue;
            };
            if token.algorithm != rule.algorithm {
                continue;
            }
            if !token.verify(key) {
                observations.push(RequestRuleObservation {
                    rule_id: rule.id.clone(),
                    outcome: "original_signature_invalid_unchanged".into(),
                    offset_seconds: None,
                });
                continue;
            }
            if !token.has_time_claims() {
                continue;
            }
            let recorded = jwt::request_timestamp(request)?;
            let offset = now
                .timestamp()
                .checked_sub(recorded.timestamp())
                .ok_or_else(|| anyhow::anyhow!("JWT time offset overflow"))?;
            let shifted = token.shift(offset, key)?;
            jwt::replace_request_token(request, &location, shifted)?;
            transformed.insert(location);
            observations.push(RequestRuleObservation {
                rule_id: rule.id.clone(),
                outcome: "time_shifted_signature_verified".into(),
                offset_seconds: Some(offset),
            });
        }
        Ok(observations)
    }
}

#[cfg(test)]
pub(crate) mod tests;
