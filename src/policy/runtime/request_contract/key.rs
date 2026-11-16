//! Case-local key time and identity validation; bindings commit with matched exchanges only.
mod config;
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub(crate) use config::{IdentityField, IdentityReference, KeyContract, KeyFormat, Transform};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BindingScope {
    case: String,
    host: String,
    port: u16,
    database: i64,
    username: Option<String>,
}
impl BindingScope {
    pub(super) fn belongs_to(&self, case: &str) -> bool {
        self.case == case
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyBindingReport {
    pub case_id: String,
    pub host: String,
    pub port: u16,
    pub database: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
}
pub(super) type PendingBinding = (BindingScope, String, String);

fn scope(context: &RedisRequestContext<'_>) -> BindingScope {
    BindingScope {
        case: context.case.into(),
        host: crate::replay::normalize_host(&context.target.host),
        port: context.target.port,
        database: context.database,
        username: context.username.map(str::to_owned),
    }
}
fn fingerprint(value: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
}
fn value<'a>(text: &'a str, template: &str) -> Result<&'a str> {
    let (prefix, suffix) = config::affixes(template)?;
    let extracted = text
        .strip_prefix(prefix)
        .and_then(|v| v.strip_suffix(suffix))
        .context("key/reference fixed affixes changed")?;
    ensure!(
        !extracted.is_empty() && extracted.len() <= 1024 && !extracted.contains(char::is_control),
        "invalid identity slot"
    );
    Ok(extracted)
}

fn selected_identity<'a>(
    text: &'a str,
    selector: &traffic_protocol_redis::key_selector::RedisValueKeySelector,
) -> Result<Option<&'a str>> {
    use traffic_protocol_redis::key_selector::RedisValueKeySelector;
    let (prefix, suffix) = match selector {
        RedisValueKeySelector::Affix { prefix, suffix }
        | RedisValueKeySelector::Numeric { prefix, suffix } => (prefix, suffix),
        RedisValueKeySelector::Exact { .. } => return Ok(None),
    };
    let middle = text
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .context("captured Redis identity is outside its physical key selector")?;
    ensure!(!middle.is_empty(), "captured Redis key identity is empty");
    Ok(Some(middle))
}
fn shaped(value: &str, format: &KeyFormat) -> bool {
    match format {
        KeyFormat::Hex { bytes } => {
            value.len() == bytes * 2
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        }
        KeyFormat::Base64url { bytes } => URL_SAFE_NO_PAD
            .decode(value)
            .ok()
            .is_some_and(|v| v.len() == *bytes && URL_SAFE_NO_PAD.encode(v) == value),
        KeyFormat::UuidV4 => uuid::Uuid::parse_str(value).ok().is_some_and(|v| {
            v.get_version_num() == 4
                && v.get_variant() == uuid::Variant::RFC4122
                && v.to_string() == value
        }),
    }
}
fn transform(value: &str, kind: Transform) -> String {
    match kind {
        Transform::Identity => value.into(),
        Transform::Sha256 => format!("{:x}", Sha256::digest(value.as_bytes())),
    }
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compare_key(
        &self,
        context: &RedisRequestContext<'_>,
        rule: &ReplayDependencyRule,
        selector: &super::config::RedisRequestSelector,
        source: &[u8],
        actual: &[u8],
        clocks: crate::primary_protocol::assertion::RequestTimes,
        decision: &mut Decision,
    ) -> Result<()> {
        let case = context.case;
        let Some(contract) = &selector.key_contract else {
            ensure!(
                source == actual
                    || std::str::from_utf8(source)
                        .ok()
                        .zip(std::str::from_utf8(actual).ok())
                        .is_some_and(|(a, b)| self
                            .knows_native_identity(case, a, b)
                            .unwrap_or(false)),
                "Redis key changed without an accepted complete identity relation"
            );
            return Ok(());
        };
        let left = std::str::from_utf8(source)?;
        let right = std::str::from_utf8(actual)?;
        ensure!(
            left.len() <= 1024 && right.len() <= 1024 && selector.key.matches(actual),
            "target key is outside its declared selector"
        );
        match contract {
            KeyContract::TimeWindow {
                window_seconds,
                separator,
                segment_index,
            } => {
                let mut a = left.split(*separator).collect::<Vec<_>>();
                let mut b = right.split(*separator).collect::<Vec<_>>();
                ensure!(
                    !a.is_empty() && a.len() == b.len() && a.len() <= 64,
                    "key window structure changed"
                );
                let index = segment_index.unwrap_or(a.len() - 1);
                ensure!(index < a.len(), "key window segment is absent");
                for (slot, clock) in [(a[index], clocks.source), (b[index], clocks.target)] {
                    let clock =
                        clock.context("key time window requires both dependency request starts")?;
                    let number = slot
                        .parse::<i64>()
                        .context("key window must be an integer")?;
                    ensure!(
                        number.to_string() == slot,
                        "key window requires canonical integer spelling"
                    );
                    let period = i64::from(*window_seconds);
                    let low = clock
                        .timestamp()
                        .checked_sub(5)
                        .context("window clock underflow")?
                        .div_euclid(period);
                    let high = clock
                        .timestamp()
                        .checked_add(5)
                        .context("window clock overflow")?
                        .div_euclid(period);
                    ensure!(
                        (low..=high).contains(&number),
                        "key window differs from its own request clock"
                    );
                }
                a[index] = "";
                b[index] = "";
                ensure!(a == b, "stable Redis key segments changed");
                decision.time_validations += 1;
            }
            KeyContract::Capture { template, format } => {
                let a = value(left, template)?;
                let b = value(right, template)?;
                ensure!(
                    shaped(a, format) && shaped(b, format),
                    "key identity format changed"
                );
                let scope = scope(context);
                let state = self.state.lock().expect("request contracts");
                let pairs = state
                    .key_bindings
                    .iter()
                    .filter(|(other, _)| other.case == case)
                    .flat_map(|(_, pairs)| pairs.iter())
                    .collect::<Vec<_>>();
                let (source_hash, target_hash) = (fingerprint(a), fingerprint(b));
                ensure!(
                    state
                        .key_binding_proofs
                        .iter()
                        .filter(|p| p.case_id == scope.case)
                        .all(|p| (p.source_fingerprint != source_hash
                            || p.target_fingerprint == target_hash)
                            && (p.target_fingerprint != target_hash
                                || p.source_fingerprint == source_hash)),
                    "key capture conflicts with its committed evidence"
                );
                ensure!(
                    (pairs.iter().any(|(source, _)| source.as_str() == a) || pairs.len() < 4096)
                        && pairs
                            .iter()
                            .all(|(x, y)| (x.as_str() != a || y.as_str() == b)
                                && (y.as_str() != b || x.as_str() == a)),
                    "key identity binding changed or collapsed"
                );
                ensure!(
                    decision
                        .key_bindings
                        .iter()
                        .filter(|(s, _, _)| s.case == case)
                        .all(|(_, x, y)| (x != a || y == b) && (y != b || x == a)),
                    "pending key identities conflict"
                );
                drop(state);
                self.observe_native_identity(case, a, b, decision)?;
                if let (Some(source), Some(target)) = (
                    selected_identity(left, &selector.key)?,
                    selected_identity(right, &selector.key)?,
                ) {
                    // A format's literal prefix is part of its complete typed
                    // identity, just as it is in a JSON field. The random
                    // suffix alone cannot establish that cross-carrier pair.
                    self.observe_native_identity(case, source, target, decision)?;
                }
                if left.len() <= 1024 && right.len() <= 1024 {
                    self.observe_native_identity(case, left, right, decision)?;
                }
                decision.key_bindings.push((scope, a.into(), b.into()));
            }
            KeyContract::Reference {
                template,
                transform,
            } => self.compare_identity(
                case,
                rule,
                context.database,
                &IdentityReference {
                    template: template.clone(),
                    transform: *transform,
                },
                left,
                right,
                decision,
            )?,
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compare_identity(
        &self,
        case: &str,
        rule: &ReplayDependencyRule,
        database: i64,
        reference: &IdentityReference,
        source: &str,
        actual: &str,
        decision: &mut Decision,
    ) -> Result<()> {
        let a = value(source, &reference.template)?;
        let b = value(actual, &reference.template)?;
        let _ = (rule, database);
        if matches!(reference.transform, Transform::Identity)
            && self.knows_native_identity(case, a, b)?
        {
            if source.len() <= 1024 && actual.len() <= 1024 {
                self.observe_native_identity(case, source, actual, decision)?;
            }
            decision.identity_references += 1;
            return Ok(());
        }
        let matches = |x: &str, y: &str| {
            transform(x, reference.transform) == a && transform(y, reference.transform) == b
        };
        if decision
            .key_bindings
            .iter()
            .any(|(s, x, y)| s.case == case && matches(x, y))
        {
            self.observe_native_identity(case, a, b, decision)?;
            if source.len() <= 1024 && actual.len() <= 1024 {
                self.observe_native_identity(case, source, actual, decision)?;
            }
            decision.identity_references += 1;
            return Ok(());
        }
        let state = self.state.lock().expect("request contracts");
        if state
            .key_bindings
            .iter()
            .filter(|(other, _)| other.case == case)
            .any(|(_, pairs)| pairs.iter().any(|(x, y)| matches(x, y)))
        {
            drop(state);
            self.observe_native_identity(case, a, b, decision)?;
            if source.len() <= 1024 && actual.len() <= 1024 {
                self.observe_native_identity(case, source, actual, decision)?;
            }
            decision.identity_references += 1;
            return Ok(());
        }
        let (a, b) = match reference.transform {
            Transform::Identity => (fingerprint(a), fingerprint(b)),
            Transform::Sha256 => (format!("sha256:{a}"), format!("sha256:{b}")),
        };
        ensure!(
            state.key_binding_proofs.iter().any(|p| p.case_id == case
                && p.source_fingerprint == a
                && p.target_fingerprint == b),
            "identity reference has no matching committed capture"
        );
        drop(state);
        if source.len() <= 1024 && actual.len() <= 1024 {
            self.observe_native_identity(case, source, actual, decision)?;
        }
        decision.identity_references += 1;
        Ok(())
    }
    pub(crate) fn key_binding_report(&self) -> Vec<KeyBindingReport> {
        let state = self.state.lock().expect("request contracts");
        state
            .key_bindings
            .iter()
            .flat_map(|(s, pairs)| {
                pairs.iter().map(|(a, b)| KeyBindingReport {
                    case_id: s.case.clone(),
                    host: s.host.clone(),
                    port: s.port,
                    database: s.database,
                    username: s.username.clone(),
                    source_fingerprint: fingerprint(a),
                    target_fingerprint: fingerprint(b),
                })
            })
            .collect()
    }
}

#[cfg(test)]
impl RequestContracts {
    pub(super) fn restore_key_binding_proofs(&self, report: &Value) -> Result<()> {
        let mut state = self.state.lock().expect("request contracts");
        let mut proofs = state.key_binding_proofs.clone();
        for proof in report["replay_policy"]["key_bindings"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let proof: KeyBindingReport = serde_json::from_value(proof.clone())?;
            let hash = |s: &str| {
                s.len() == 71
                    && s.starts_with("sha256:")
                    && s[7..]
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            };
            ensure!(
                !proof.case_id.is_empty()
                    && proof.case_id.len() <= 255
                    && !proof.host.is_empty()
                    && proof.host.len() <= 255
                    && proof.host == proof.host.to_ascii_lowercase()
                    && proof.port > 0
                    && proof.database >= 0
                    && hash(&proof.source_fingerprint)
                    && hash(&proof.target_fingerprint),
                "invalid committed key binding proof"
            );
            IdentityReference {
                template: "{value}".into(),
                transform: Transform::Identity,
            }
            .validate()?;
            ensure!(
                proofs
                    .iter()
                    .filter(|p| p.case_id == proof.case_id)
                    .all(|p| (p.source_fingerprint != proof.source_fingerprint
                        || p.target_fingerprint == proof.target_fingerprint)
                        && (p.target_fingerprint != proof.target_fingerprint
                            || p.source_fingerprint == proof.source_fingerprint)),
                "committed key binding proofs changed or collapsed an identity"
            );
            ensure!(proofs.len() < 16384, "key binding proof bound exceeded");
            proofs.insert(proof);
        }
        state.key_binding_proofs = proofs;
        Ok(())
    }
}
