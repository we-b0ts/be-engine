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
    binding: String,
}
impl BindingScope {
    pub(super) fn belongs_to(&self, case: &str) -> bool {
        self.case == case
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct KeyBindingReport {
    pub case_id: String,
    pub host: String,
    pub port: u16,
    pub database: i64,
    pub binding: String,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
}
pub(super) type PendingBinding = (BindingScope, String, String);

fn scope(case: &str, rule: &ReplayDependencyRule, database: i64, binding: &str) -> BindingScope {
    BindingScope {
        case: case.into(),
        host: rule
            .target
            .host
            .as_ref()
            .expect("validated endpoint")
            .to_ascii_lowercase(),
        port: rule.target.port.expect("validated endpoint"),
        database,
        binding: binding.into(),
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
        case: &str,
        rule: &ReplayDependencyRule,
        selector: &super::config::RedisRequestSelector,
        source: &[u8],
        actual: &[u8],
        decision: &mut Decision,
    ) -> Result<()> {
        let Some(contract) = &selector.key_contract else {
            ensure!(source == actual, "Redis key changed");
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
                let clocks = self.request_times(case);
                for (slot, clock) in [(a[index], clocks.source), (b[index], clocks.target)] {
                    let clock = clock.context("key time window requires both request anchors")?;
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
            KeyContract::Capture {
                binding,
                template,
                format,
            } => {
                let a = value(left, template)?;
                let b = value(right, template)?;
                ensure!(
                    shaped(a, format) && shaped(b, format),
                    "key identity format changed"
                );
                let scope = scope(case, rule, selector.database, binding);
                let state = self.state.lock().expect("request contracts");
                let pairs = state.key_bindings.get(&scope);
                let (source_hash, target_hash) = (fingerprint(a), fingerprint(b));
                ensure!(
                    state
                        .key_binding_proofs
                        .iter()
                        .filter(|p| p.case_id == scope.case
                            && p.host == scope.host
                            && p.port == scope.port
                            && p.database == scope.database
                            && p.binding == scope.binding)
                        .all(|p| (p.source_fingerprint != source_hash
                            || p.target_fingerprint == target_hash)
                            && (p.target_fingerprint != target_hash
                                || p.source_fingerprint == source_hash)),
                    "key capture conflicts with its committed evidence"
                );
                ensure!(
                    pairs.is_none_or(|pairs| (pairs.contains_key(a) || pairs.len() < 256)
                        && pairs
                            .iter()
                            .all(|(x, y)| (x != a || y == b) && (y != b || x == a))),
                    "key identity binding changed or collapsed"
                );
                ensure!(
                    decision
                        .key_bindings
                        .iter()
                        .filter(|(s, _, _)| *s == scope)
                        .all(|(_, x, y)| (x != a || y == b) && (y != b || x == a)),
                    "pending key identities conflict"
                );
                decision.key_bindings.push((scope, a.into(), b.into()));
            }
            KeyContract::Reference {
                binding,
                template,
                transform,
            } => self.compare_identity(
                case,
                rule,
                selector.database,
                &IdentityReference {
                    binding: binding.clone(),
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
        let scope = scope(case, rule, database, &reference.binding);
        let matches = |x: &str, y: &str| {
            transform(x, reference.transform) == a && transform(y, reference.transform) == b
        };
        if decision
            .key_bindings
            .iter()
            .any(|(s, x, y)| *s == scope && matches(x, y))
        {
            decision.identity_references += 1;
            return Ok(());
        }
        let state = self.state.lock().expect("request contracts");
        if state
            .key_bindings
            .get(&scope)
            .is_some_and(|pairs| pairs.iter().any(|(x, y)| matches(x, y)))
        {
            decision.identity_references += 1;
            return Ok(());
        }
        let (a, b) = match reference.transform {
            Transform::Identity => (fingerprint(a), fingerprint(b)),
            Transform::Sha256 => (format!("sha256:{a}"), format!("sha256:{b}")),
        };
        ensure!(
            state.key_binding_proofs.iter().any(|p| p.case_id == case
                && p.host == scope.host
                && p.port == scope.port
                && p.database == database
                && p.binding == reference.binding
                && p.source_fingerprint == a
                && p.target_fingerprint == b),
            "identity reference has no matching committed capture"
        );
        decision.identity_references += 1;
        Ok(())
    }
    pub(in crate::replay) fn key_binding_report(&self) -> Vec<KeyBindingReport> {
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
                    binding: s.binding.clone(),
                    source_fingerprint: fingerprint(a),
                    target_fingerprint: fingerprint(b),
                })
            })
            .collect()
    }
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
                binding: proof.binding.clone(),
                template: "{value}".into(),
                transform: Transform::Identity,
            }
            .validate()?;
            ensure!(
                proofs
                    .iter()
                    .filter(|p| p.case_id == proof.case_id
                        && p.host == proof.host
                        && p.port == proof.port
                        && p.database == proof.database
                        && p.binding == proof.binding)
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
