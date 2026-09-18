//! Explicit, engine-owned transformations of recorded inbound requests.
//! Never consumes assertion or dependency response values.

pub(crate) mod jwt;
pub mod keys;
pub use jwt::Algorithm as JwtAlgorithm;
pub(crate) mod policy;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRules {
    #[serde(default, skip_serializing_if = "JwtRules::is_empty")]
    pub jwt: JwtRules,
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
    pub profile: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct JwtRules {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, JwtProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<JwtRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtProfile {
    pub signing_key_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_source: Option<keys::SigningKeySource>,
    pub algorithm: jwt::Algorithm,
    pub time: JwtTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyJwtRule {
    id: String,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    query_param: Option<String>,
    algorithm: jwt::Algorithm,
    time: JwtTime,
    signing_key_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtRulesDocument {
    #[serde(default)]
    profiles: BTreeMap<String, JwtProfile>,
    #[serde(default)]
    rules: Vec<JwtRule>,
}

impl<'de> Deserialize<'de> for JwtRules {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Profiles(JwtRulesDocument),
            Legacy(Vec<LegacyJwtRule>),
        }

        match Input::deserialize(deserializer)? {
            Input::Profiles(document) => Ok(Self {
                profiles: document.profiles,
                rules: document.rules,
            }),
            Input::Legacy(legacy_rules) => {
                let mut profiles = BTreeMap::new();
                let mut rules = Vec::with_capacity(legacy_rules.len());
                for legacy in legacy_rules {
                    let profile = legacy.id.clone();
                    profiles.insert(
                        profile.clone(),
                        JwtProfile {
                            signing_key_ref: legacy.signing_key_ref,
                            signing_key_source: None,
                            algorithm: legacy.algorithm,
                            time: legacy.time,
                        },
                    );
                    rules.push(JwtRule {
                        id: legacy.id,
                        header: legacy.header,
                        scheme: legacy.scheme,
                        query_param: legacy.query_param,
                        profile,
                    });
                }
                Ok(Self { profiles, rules })
            }
        }
    }
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

impl JwtRules {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.rules.is_empty()
    }

    pub(crate) fn add(&mut self, profile: JwtProfile, rule: JwtRule) -> Result<bool> {
        let profile_added = match self.profiles.get(&rule.profile) {
            Some(existing) => {
                ensure!(
                    existing == &profile,
                    "JWT profile already exists with different settings"
                );
                false
            }
            None => {
                self.profiles.insert(rule.profile.clone(), profile);
                true
            }
        };
        if let Some(existing) = self.rules.iter().find(|existing| existing.id == rule.id) {
            ensure!(
                existing == &rule,
                "JWT request rule id already exists with different settings"
            );
            return Ok(profile_added);
        }
        self.rules.push(rule);
        self.validate()?;
        Ok(true)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.profiles.len() <= 32,
            "at most 32 JWT request profiles are supported"
        );
        ensure!(
            self.rules.len() <= 32,
            "at most 32 JWT request rules are supported"
        );
        for (id, profile) in &self.profiles {
            keys::validate_reference(id)?;
            keys::validate_reference(&profile.signing_key_ref)?;
            if let Some(source) = &profile.signing_key_source {
                keys::validate_source(source)?;
            }
        }
        let mut ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for rule in &self.rules {
            keys::validate_reference(&rule.id)?;
            keys::validate_reference(&rule.profile)?;
            ensure!(ids.insert(&rule.id), "duplicate JWT request rule id");
            let profile = self.profiles.get(&rule.profile).with_context(|| {
                format!(
                    "JWT request rule {:?} references an unknown profile",
                    rule.id
                )
            })?;
            let location = rule.location()?;
            let (location_kind, location_name) = location.selector_key();
            ensure!(
                selectors.insert((
                    location_kind.to_string(),
                    location_name.to_string(),
                    profile.algorithm,
                    profile.signing_key_ref.clone()
                )),
                "duplicate JWT request selector and key"
            );
        }
        Ok(())
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
        self.jwt.validate()
    }
}

pub(crate) struct RequestRuleRuntime {
    rules: Vec<RuntimeJwtRule>,
}

struct RuntimeJwtRule {
    rule: JwtRule,
    profile: JwtProfile,
    key: RuntimeKey,
}

enum RuntimeKey {
    TargetStartup(PathBuf),
    #[cfg(test)]
    Fixed(Vec<u8>),
}

impl RequestRuleRuntime {
    pub(crate) fn load(target_root: &Path, policy: &Path) -> Result<Self> {
        let configured = policy::load(policy)?;
        let mut rules = Vec::with_capacity(configured.jwt.rules.len());
        for rule in configured.jwt.rules {
            let profile = configured
                .jwt
                .profiles
                .get(&rule.profile)
                .cloned()
                .with_context(|| {
                    format!(
                        "JWT request rule {:?} references an unknown profile",
                        rule.id
                    )
                })?;
            rules.push(RuntimeJwtRule {
                rule,
                profile,
                key: RuntimeKey::TargetStartup(target_root.to_path_buf()),
            });
        }
        Ok(Self { rules })
    }

    #[cfg(test)]
    pub(crate) fn with_test_keys(rules: Vec<(JwtRule, JwtProfile, Vec<u8>)>) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|(rule, profile, key)| RuntimeJwtRule {
                    rule,
                    profile,
                    key: RuntimeKey::Fixed(key),
                })
                .collect(),
        }
    }

    pub(crate) fn apply(
        &self,
        request: &mut Value,
        now: DateTime<Utc>,
    ) -> Result<Vec<RequestRuleObservation>> {
        let mut observations = Vec::new();
        let mut transformed = BTreeSet::new();
        for configured in &self.rules {
            let rule = &configured.rule;
            let profile = &configured.profile;
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
            if token.algorithm != profile.algorithm {
                continue;
            }
            if !token.has_time_claims() {
                continue;
            }
            let key = match &configured.key {
                RuntimeKey::TargetStartup(root) => {
                    let source = profile.signing_key_source.as_ref().with_context(|| {
                        format!(
                            "JWT request rule {:?} matched a parseable JWT requiring time translation, but profile {:?} has no signing_key_source in verification.yaml",
                            rule.id, rule.profile
                        )
                    })?;
                    Cow::Owned(keys::resolve_source(root, source).with_context(|| {
                        format!(
                            "JWT request rule {:?} cannot resolve its signing_key_source from target startup inputs",
                            rule.id
                        )
                    })?)
                }
                #[cfg(test)]
                RuntimeKey::Fixed(key) => Cow::Borrowed(key.as_slice()),
            };
            if !token.verify(&key) {
                observations.push(RequestRuleObservation {
                    rule_id: rule.id.clone(),
                    outcome: "original_signature_invalid_unchanged".into(),
                    offset_seconds: None,
                });
                continue;
            }
            let recorded = jwt::request_timestamp(request)?;
            let offset = now
                .timestamp()
                .checked_sub(recorded.timestamp())
                .ok_or_else(|| anyhow::anyhow!("JWT time offset overflow"))?;
            let shifted = token.shift(offset, &key)?;
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
