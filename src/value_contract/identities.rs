//! Bounded case-local renaming shared by physical resource positions.
//! Parsing and hashing are prepared before acquiring a runtime store mutex.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy::IdentityFormat;

const MAX_CASE_ENTITIES: usize = 4096;
const MAX_RUN_ENTITIES: usize = 32768;
const MAX_PROPOSAL_PAIRS: usize = 16384;
const MAX_PROPOSAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUN_BYTES: usize = 64 * 1024 * 1024;
type Fingerprint = [u8; 32];

/// Private control/runtime data. Never include tokens in diagnostic reports.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityPair {
    // Canonical JSON scalars preserve string/number types and full prefixes.
    // These private keys are never authored or included in public reports.
    pub(crate) source: String,
    pub(crate) target: String,
}

impl std::fmt::Debug for IdentityPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityPair")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PreparedPair {
    pair: IdentityPair,
    source: Fingerprint,
    target: Fingerprint,
}

impl PreparedPair {
    fn prepare(pair: IdentityPair) -> Result<Self> {
        let mut representation = None;
        for encoded in [&pair.source, &pair.target] {
            ensure!(
                encoded.len() <= 64 * 1024 * 6 + 2,
                "identity scalar exceeds its bounded representation"
            );
            let value: Value = serde_json::from_str(encoded)
                .context("identity scalar requires its complete typed representation")?;
            if pair.source != pair.target {
                ensure!(
                    value.is_i64()
                        || value.is_u64()
                        || value.as_str().is_some_and(|text| !text.is_empty()),
                    "non-generated scalar identities only permit exact anchors"
                );
            }
            let scalar_type = std::mem::discriminant(&value);
            ensure!(
                representation.is_none_or(|previous| previous == scalar_type),
                "identity scalar representation changed"
            );
            representation = Some(scalar_type);
            ensure!(
                super::json::identity::key(&value, "").is_ok_and(|canonical| canonical == *encoded),
                "identity scalar requires its complete typed representation"
            );
        }
        Ok(Self {
            source: Sha256::digest(pair.source.as_bytes()).into(),
            target: Sha256::digest(pair.target.as_bytes()).into(),
            pair,
        })
    }
}

#[derive(Clone)]
pub(crate) struct IdentityDecision {
    case: String,
    pairs: Vec<PreparedPair>,
}

impl std::fmt::Debug for IdentityDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityDecision")
            .field("pairs", &self.pairs.len())
            .finish_non_exhaustive()
    }
}

impl IdentityDecision {
    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub(crate) fn prepare(case: &str, pairs: Vec<IdentityPair>) -> Result<Self> {
        ensure!(
            !case.is_empty() && case.len() <= 512,
            "invalid identity case scope"
        );
        ensure!(
            pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity proposal bound exceeded"
        );
        ensure!(
            pairs
                .iter()
                .map(|pair| pair.source.len() + pair.target.len())
                .sum::<usize>()
                <= MAX_PROPOSAL_BYTES,
            "identity proposal byte bound exceeded"
        );
        Ok(Self {
            case: case.to_owned(),
            pairs: pairs
                .into_iter()
                .map(PreparedPair::prepare)
                .collect::<Result<_>>()?,
        })
    }

    pub(crate) fn merge(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.case == other.case,
            "identity proposals have different case scopes"
        );
        ensure!(
            self.pairs.len() + other.pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity proposal bound exceeded"
        );
        ensure!(
            self.pairs
                .iter()
                .chain(&other.pairs)
                .map(|pair| pair.pair.source.len() + pair.pair.target.len())
                .sum::<usize>()
                <= MAX_PROPOSAL_BYTES,
            "identity proposal byte bound exceeded"
        );
        self.pairs.extend(other.pairs);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Case {
    forward: BTreeMap<Fingerprint, (Fingerprint, Arc<str>)>,
    reverse: BTreeMap<Fingerprint, Fingerprint>,
    entities: usize,
    bytes: usize,
}

#[derive(Default)]
pub(crate) struct IdentityStore {
    cases: BTreeMap<String, Case>,
    entities: usize,
    bytes: usize,
}

impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityStore")
            .field("cases", &self.cases.len())
            .field("entities", &self.entities)
            .finish()
    }
}

impl IdentityStore {
    pub(crate) fn begin_case(&mut self, case: &str) {
        if let Some(case) = self.cases.remove(case) {
            self.entities -= case.entities;
            self.bytes -= case.bytes;
        }
    }

    #[cfg(test)]
    pub(crate) fn has_case(&self, case: &str) -> bool {
        self.cases.get(case).is_some_and(|case| case.entities > 0)
    }

    /// Validate committed correspondences plus a small proposal-local overlay.
    /// No state changes are visible until `commit` validates every pair again.
    pub(crate) fn validate(&self, decision: &IdentityDecision) -> Result<()> {
        ensure!(
            decision.pairs.len() <= MAX_PROPOSAL_PAIRS
                && decision
                    .pairs
                    .iter()
                    .map(|pair| pair.pair.source.len() + pair.pair.target.len())
                    .sum::<usize>()
                    <= MAX_PROPOSAL_BYTES,
            "identity proposal bound exceeded"
        );
        let case = self.cases.get(&decision.case);
        let mut forward = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        let mut added = 0;
        let mut added_bytes = 0;
        for pair in &decision.pairs {
            let source = pair.source;
            let target = pair.target;
            ensure!(
                case.and_then(|case| case.forward.get(&pair.source))
                    .is_none_or(|(target, _)| target == &pair.target)
                    && case
                        .and_then(|case| case.reverse.get(&pair.target))
                        .is_none_or(|source| source == &pair.source)
                    && forward
                        .get(&source)
                        .is_none_or(|target| target == &pair.target)
                    && reverse
                        .get(&target)
                        .is_none_or(|source| source == &pair.source),
                "identity equality relationship changed"
            );
            if case.is_none_or(|case| !case.forward.contains_key(&pair.source))
                && !forward.contains_key(&source)
            {
                added += 1;
                added_bytes += pair.pair.target.len();
            }
            forward.insert(source, pair.target);
            reverse.insert(target, pair.source);
        }
        ensure!(
            case.map_or(0, |case| case.entities) + added <= MAX_CASE_ENTITIES,
            "identity relationship exceeds 4096 entities per case"
        );
        ensure!(
            self.entities + added <= MAX_RUN_ENTITIES,
            "identity relationship exceeds 32768 entities per replay"
        );
        ensure!(
            case.map_or(0, |case| case.bytes) + added_bytes <= MAX_CASE_BYTES,
            "identity relationship exceeds its per-case byte bound"
        );
        ensure!(
            self.bytes + added_bytes <= MAX_RUN_BYTES,
            "identity relationship exceeds its replay byte bound"
        );
        Ok(())
    }

    /// Isolated delivery view of an accepted candidate's staged relationships.
    /// Shared token storage keeps this bounded snapshot independent of JWT size;
    /// run counters retain all other cases so ordinary capacity checks still apply.
    pub(crate) fn preview(&self, decision: IdentityDecision) -> Result<Self> {
        self.validate(&decision)?;
        let cases = self
            .cases
            .get(&decision.case)
            .map(|case| BTreeMap::from([(decision.case.clone(), case.clone())]))
            .unwrap_or_default();
        let mut preview = Self {
            cases,
            entities: self.entities,
            bytes: self.bytes,
        };
        preview.commit(decision)?;
        Ok(preview)
    }

    pub(crate) fn contains_pair(&self, case: &str, pair: IdentityPair) -> Result<bool> {
        let pair = PreparedPair::prepare(pair)?;
        Ok(self
            .cases
            .get(case)
            .and_then(|case| case.forward.get(&pair.source))
            .is_some_and(|(target, _)| *target == pair.target))
    }

    pub(crate) fn commit(&mut self, decision: IdentityDecision) -> Result<()> {
        self.validate(&decision)?;
        if decision.pairs.is_empty() {
            return Ok(());
        }
        let case = self.cases.entry(decision.case).or_default();
        for pair in decision.pairs {
            if case.forward.contains_key(&pair.source) {
                continue;
            }
            case.bytes += pair.pair.target.len();
            self.bytes += pair.pair.target.len();
            case.forward
                .insert(pair.source, (pair.target, pair.pair.target.into()));
            case.reverse.insert(pair.target, pair.source);
            case.entities += 1;
            self.entities += 1;
        }
        Ok(())
    }

    /// A recorded read is an input. Known entities deliver their Target token;
    /// an unknown historical entity is fixed to its delivered Source value.
    pub(crate) fn deliveries(
        &self,
        case: &str,
        selected: &[PreparedIdentityDelivery],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        ensure!(
            !case.is_empty() && case.len() <= 512,
            "invalid identity case scope"
        );
        let committed = self.cases.get(case);
        let mut values = Vec::with_capacity(selected.len());
        let mut pairs = Vec::with_capacity(selected.len());
        for selected in selected {
            let target = committed.and_then(|case| case.forward.get(&selected.source_hash));
            let (target_hash, token) = target
                .map(|(hash, token)| (*hash, token.as_ref()))
                .unwrap_or((selected.source_hash, selected.source.as_str()));
            let value: Value =
                serde_json::from_str(token).context("invalid typed identity delivery")?;
            super::json::identity::token(&value, &selected.prefix, selected.format, "")
                .map_err(|difference| anyhow::anyhow!(difference.reason))?;
            values.push(value);
            pairs.push(PreparedPair {
                pair: IdentityPair {
                    source: selected.source.clone(),
                    target: token.to_owned(),
                },
                source: selected.source_hash,
                target: target_hash,
            });
        }
        let decision = IdentityDecision {
            case: case.into(),
            pairs,
        };
        ensure!(
            decision.pairs.len() <= MAX_PROPOSAL_PAIRS,
            "identity delivery proposal bound exceeded"
        );
        self.validate(&decision)?;
        Ok((values, decision))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct IdentityDelivery<'a> {
    pub(crate) prefix: &'a str,
    pub(crate) format: IdentityFormat,
    pub(crate) value: &'a Value,
}

impl IdentityDelivery<'_> {
    pub(crate) fn token(self) -> Result<String> {
        super::json::identity::token(self.value, self.prefix, self.format, "")
            .map_err(|difference| anyhow::anyhow!(difference.reason))?;
        super::json::identity::key(self.value, "")
            .map_err(|difference| anyhow::anyhow!(difference.reason))
    }
}

pub(crate) struct PreparedIdentityDelivery {
    prefix: String,
    source: String,
    source_hash: Fingerprint,
    format: IdentityFormat,
}

impl PreparedIdentityDelivery {
    pub(crate) fn prepare(selected: IdentityDelivery<'_>) -> Result<Self> {
        let source = selected.token()?;
        Ok(Self {
            prefix: selected.prefix.to_owned(),
            source_hash: Sha256::digest(source.as_bytes()).into(),
            source,
            format: selected.format,
        })
    }
}

#[cfg(test)]
mod tests;
