//! Explicit, engine-owned transformations of recorded inbound requests.
//! Request execution never consumes assertion or dependency response values.
//! Pure JWT primitives are also reused by isolated assertion comparators.

mod derived;
pub(crate) mod jwt;
pub mod keys;
mod socketio_connect;
pub use jwt::Algorithm as JwtAlgorithm;
pub use jwt::nonce::{
    DynamicClaim as JwtDynamicClaim, NonceClaim as JwtNonceClaim, NonceFormat as JwtNonceFormat,
};
pub(crate) mod policy;
pub(crate) mod signed_timestamp;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socketio_connect: Option<SocketIoConnectLocation>,
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
                        socketio_connect: None,
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
    BearerHeader {
        header: String,
    },
    RawHeader {
        raw_header: String,
    },
    QueryParameter {
        query_param: String,
    },
    SocketIoConnect {
        socketio_connect: SocketIoConnectLocation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketIoConnectLocation {
    pub namespace: String,
    pub pointer: String,
}

impl SocketIoConnectLocation {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.namespace.starts_with('/')
                && self.namespace.len() <= 1024
                && !self.namespace.chars().any(|c| c.is_control() || c == ','),
            "Socket.IO CONNECT JWT requires an exact bounded namespace"
        );
        crate::policy::validate_pointer(&self.pointer, false)
    }
}

impl JwtTokenLocation {
    fn selector_key(&self) -> (&'static str, String) {
        match self {
            Self::BearerHeader { header } => ("header", header.clone()),
            Self::RawHeader { raw_header } => ("header", raw_header.clone()),
            Self::QueryParameter { query_param } => ("query_param", query_param.clone()),
            Self::SocketIoConnect { socketio_connect } => (
                "socketio_connect",
                serde_json::to_string(socketio_connect).expect("string selector"),
            ),
        }
    }
}

impl JwtRule {
    pub(crate) fn location(&self) -> Result<JwtTokenLocation> {
        match (
            &self.header,
            &self.scheme,
            &self.query_param,
            &self.socketio_connect,
        ) {
            (Some(header), Some(scheme), None, None) => {
                ensure!(
                    scheme == "bearer" || scheme == "raw",
                    "JWT header rules require bearer or raw scheme"
                );
                ensure!(
                    hyper::header::HeaderName::from_bytes(header.as_bytes()).is_ok(),
                    "invalid JWT header name"
                );
                ensure!(
                    header == &header.to_ascii_lowercase(),
                    "JWT header must be lowercase"
                );
                Ok(if scheme == "raw" {
                    JwtTokenLocation::RawHeader {
                        raw_header: header.clone(),
                    }
                } else {
                    JwtTokenLocation::BearerHeader {
                        header: header.clone(),
                    }
                })
            }
            (None, None, Some(query_param), None) => {
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
            (None, None, None, Some(location)) => {
                location.validate()?;
                Ok(JwtTokenLocation::SocketIoConnect {
                    socketio_connect: location.clone(),
                })
            }
            _ => anyhow::bail!(
                "JWT rule must select exactly one header with an explicit scheme, query_param, or socketio_connect"
            ),
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
    signed_timestamps: Vec<(crate::policy::NativeRule, PathBuf)>,
}

struct RuntimeJwtRule {
    rule: JwtRule,
    profile: JwtProfile,
    key: RuntimeKey,
    scope: Option<(
        crate::policy::NativeMatch,
        Option<crate::policy::SourceCondition>,
    )>,
}

enum RuntimeKey {
    TargetStartup(PathBuf),
    Frozen(keys::ResolvedSigningKey),
    #[cfg(test)]
    Fixed(Vec<u8>),
}

impl RequestRuleRuntime {
    pub(crate) fn load(target_root: &Path, policy: &Path) -> Result<Self> {
        let document = crate::policy::parse_policy(&std::fs::read_to_string(policy)?)?;
        let compiled = crate::policy::compile_policy(&document)?;
        Self::from_compiled(target_root, &compiled)
    }

    pub(crate) fn from_compiled(
        target_root: &Path,
        compiled: &crate::policy::CompiledPolicy,
    ) -> Result<Self> {
        let configured = crate::policy::runtime::compiled_input_rules(compiled)?;
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
            let source_scope = compiled
                .native
                .iter()
                .find(|native| native.rule.id == rule.id)
                .context("input JWT lost its compiled Source scope")?;
            rules.push(RuntimeJwtRule {
                rule,
                profile,
                key: RuntimeKey::TargetStartup(target_root.to_path_buf()),
                scope: Some((
                    source_scope.rule.selector.clone(),
                    source_scope.rule.when.clone(),
                )),
            });
        }
        let signed_timestamps = compiled
            .native
            .iter()
            .filter(|native| {
                matches!(
                    native.rule.effect,
                    crate::policy::NativeEffect::InputSignedTimestamp(_)
                )
            })
            .map(|native| (native.rule.clone(), target_root.to_path_buf()))
            .collect();
        Ok(Self {
            rules,
            signed_timestamps,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_keys(rules: Vec<(JwtRule, JwtProfile, Vec<u8>)>) -> Self {
        Self {
            signed_timestamps: Vec::new(),
            rules: rules
                .into_iter()
                .map(|(rule, profile, key)| RuntimeJwtRule {
                    rule,
                    profile,
                    key: RuntimeKey::Fixed(key),
                    scope: None,
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
        let source_method = request["method"].as_str().unwrap_or_default().to_string();
        let source_path = request["uri"]
            .as_str()
            .and_then(|uri| uri.parse::<hyper::Uri>().ok())
            .map(|uri| uri.path().to_string())
            .unwrap_or_default();
        let source_body = crate::primary_protocol::assertion::native::source_request_body(request);
        for configured in &self.rules {
            if let Some((scope, when)) = &configured.scope
                && (!scope.api.as_deref().is_none_or(|api| {
                    api.split_once(' ').is_some_and(|(method, path)| {
                        method == source_method
                            && crate::path_pattern::matches_path_pattern(path, &source_path)
                    })
                }) || !when.as_ref().is_none_or(|when| {
                    source_body
                        .as_ref()
                        .is_some_and(|body| when.matches_body(body))
                }))
            {
                continue;
            }
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
                            "JWT request rule {:?} matched a parseable JWT requiring time translation, but profile {:?} has no signing_key_source in project.policy",
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
                RuntimeKey::Frozen(key) => {
                    key.ensure_current()?;
                    Cow::Borrowed(key.bytes())
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
        for (rule, root) in &self.signed_timestamps {
            let Some(api) = &rule.selector.api else {
                continue;
            };
            if !api.split_once(' ').is_some_and(|(method, path)| {
                method == source_method
                    && crate::path_pattern::matches_path_pattern(path, &source_path)
            }) || !rule.when.as_ref().is_none_or(|when| {
                source_body
                    .as_ref()
                    .is_some_and(|body| when.matches_body(body))
            }) {
                continue;
            }
            let crate::policy::NativeEffect::InputSignedTimestamp(effect) = &rule.effect else {
                continue;
            };
            let key = keys::resolve_source(root, &signed_timestamp::key_source(effect))?;
            if let Some(mut observation) = signed_timestamp::apply(request, effect, &key, now)? {
                observation.rule_id = rule.id.clone();
                observations.push(observation);
            }
        }
        Ok(observations)
    }
}

#[cfg(test)]
pub(crate) mod tests;
