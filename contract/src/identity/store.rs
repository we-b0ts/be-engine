//! Bounded identity correspondences shared by physical resource positions.
//! Parsing and hashing are prepared before acquiring a runtime store mutex.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_CASE_ENTITIES: usize = 4096;
const MAX_RUN_ENTITIES: usize = 32768;
const MAX_SESSION_ENTITIES: usize = 262_144;
const SESSION_ENTITIES_PER_DEPENDENCY: usize = 8;
const MAX_PROPOSAL_PAIRS: usize = 16384;
const MAX_PROPOSAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUN_BYTES: usize = 64 * 1024 * 1024;
type Fingerprint = [u8; 32];

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityScope {
    Case(String),
    Session,
}

impl IdentityScope {
    fn validate(&self) -> Result<()> {
        if let Self::Case(case) = self {
            ensure!(
                !case.is_empty() && case.len() <= 512,
                "invalid identity case scope"
            );
        }
        Ok(())
    }
}

/// Private control/runtime data. Never include tokens in diagnostic reports.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityPair {
    // Canonical JSON scalars preserve string/number types and full prefixes.
    // These private keys are never authored or included in public reports.
    pub source: String,
    pub target: String,
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
                super::key(&value, "").is_ok_and(|canonical| canonical == *encoded),
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
pub struct IdentityDecision {
    scope: IdentityScope,
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
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn retained_bytes(&self) -> usize {
        self.pairs.capacity() * std::mem::size_of::<PreparedPair>()
            + self
                .pairs
                .iter()
                .map(|pair| pair.pair.source.capacity() + pair.pair.target.capacity())
                .sum::<usize>()
    }

    pub fn prepare(case: &str, pairs: Vec<IdentityPair>) -> Result<Self> {
        Self::prepare_in_scope(IdentityScope::Case(case.into()), pairs)
    }

    pub fn prepare_in_scope(scope: IdentityScope, pairs: Vec<IdentityPair>) -> Result<Self> {
        scope.validate()?;
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
            scope,
            pairs: pairs
                .into_iter()
                .map(PreparedPair::prepare)
                .collect::<Result<_>>()?,
        })
    }

    pub fn merge(&mut self, other: Self) -> Result<()> {
        ensure!(
            self.scope == other.scope,
            "identity proposals have different scopes"
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

#[derive(Default)]
struct Bindings {
    forward: BTreeMap<Fingerprint, (Fingerprint, Box<str>)>,
    reverse: BTreeMap<Fingerprint, Fingerprint>,
    entities: usize,
    bytes: usize,
}

#[derive(Default)]
pub struct IdentityStore {
    scopes: BTreeMap<IdentityScope, Bindings>,
    session_limit: Option<usize>,
    entities: usize,
    bytes: usize,
    revision: u64,
}

pub struct IdentityPreview {
    decision: IdentityDecision,
    forward: BTreeMap<Fingerprint, usize>,
}

impl IdentityPreview {
    fn target(&self, source: &Fingerprint) -> Option<(Fingerprint, &str)> {
        let pair = &self.decision.pairs[*self.forward.get(source)?];
        Some((pair.target, &pair.pair.target))
    }
}

impl std::fmt::Debug for IdentityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityStore")
            .field("scopes", &self.scopes.len())
            .field("entities", &self.entities)
            .finish()
    }
}

impl IdentityStore {
    /// Identifies the current committed correspondences in this store.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn advance_revision(&mut self) {
        self.revision = self
            .revision
            .checked_add(1)
            .expect("identity revision overflow");
    }

    /// Only an authenticated finite Session plan may configure this scope.
    pub fn configure_session(&mut self, dependency_count: usize) -> Result<()> {
        ensure!(
            self.session_limit.is_none(),
            "identity Session scope is already configured"
        );
        self.session_limit = Some(
            dependency_count
                .saturating_mul(SESSION_ENTITIES_PER_DEPENDENCY)
                .clamp(MAX_RUN_ENTITIES, MAX_SESSION_ENTITIES),
        );
        Ok(())
    }

    pub fn begin_case(&mut self, case: &str) {
        if let Some(case) = self.scopes.remove(&IdentityScope::Case(case.into())) {
            self.entities -= case.entities;
            self.bytes -= case.bytes;
            self.advance_revision();
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn has_case(&self, case: &str) -> bool {
        self.scopes
            .get(&IdentityScope::Case(case.into()))
            .is_some_and(|case| case.entities > 0)
    }

    /// Validate committed correspondences plus a small proposal-local overlay.
    /// No state changes are visible until `commit` validates every pair again.
    pub fn validate(&self, decision: &IdentityDecision) -> Result<()> {
        self.validate_with_preview(decision, None)
    }

    pub fn validate_with_preview(
        &self,
        decision: &IdentityDecision,
        preview: Option<&IdentityPreview>,
    ) -> Result<()> {
        ensure!(
            preview.is_none_or(|preview| preview.decision.scope == decision.scope),
            "identity proposals have different scopes"
        );
        let staged = preview
            .into_iter()
            .flat_map(|preview| &preview.decision.pairs);
        ensure!(
            preview.map_or(0, |preview| preview.decision.pairs.len()) + decision.pairs.len()
                <= MAX_PROPOSAL_PAIRS
                && staged
                    .clone()
                    .chain(&decision.pairs)
                    .map(|pair| pair.pair.source.len() + pair.pair.target.len())
                    .sum::<usize>()
                    <= MAX_PROPOSAL_BYTES,
            "identity proposal bound exceeded"
        );
        let bindings = self.scopes.get(&decision.scope);
        let mut forward = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        let mut added = 0;
        let mut added_bytes = 0;
        for pair in staged.chain(&decision.pairs) {
            let source = pair.source;
            let target = pair.target;
            ensure!(
                bindings
                    .and_then(|scope| scope.forward.get(&pair.source))
                    .is_none_or(|(target, _)| target == &pair.target)
                    && bindings
                        .and_then(|scope| scope.reverse.get(&pair.target))
                        .is_none_or(|source| source == &pair.source)
                    && forward
                        .get(&source)
                        .is_none_or(|target| target == &pair.target)
                    && reverse
                        .get(&target)
                        .is_none_or(|source| source == &pair.source),
                "identity equality relationship changed"
            );
            if bindings.is_none_or(|scope| !scope.forward.contains_key(&pair.source))
                && !forward.contains_key(&source)
            {
                added += 1;
                added_bytes += pair.pair.target.len();
            }
            forward.insert(source, pair.target);
            reverse.insert(target, pair.source);
        }
        let scope_entities = bindings.map_or(0, |scope| scope.entities) + added;
        match &decision.scope {
            IdentityScope::Session => {
                let limit = self
                    .session_limit
                    .context("identity Session scope is not configured")?;
                ensure!(
                    scope_entities <= limit,
                    "identity relationship exceeds {limit} entities per session"
                );
            }
            IdentityScope::Case(_) => {
                ensure!(
                    scope_entities <= MAX_CASE_ENTITIES,
                    "identity relationship exceeds 4096 entities per case"
                );
                let session_entities = self
                    .scopes
                    .get(&IdentityScope::Session)
                    .map_or(0, |scope| scope.entities);
                ensure!(
                    self.entities - session_entities + added <= MAX_RUN_ENTITIES,
                    "identity relationship exceeds 32768 entities per replay"
                );
                ensure!(
                    bindings.map_or(0, |scope| scope.bytes) + added_bytes <= MAX_CASE_BYTES,
                    "identity relationship exceeds its per-case byte bound"
                );
            }
        }
        ensure!(
            self.bytes + added_bytes <= MAX_RUN_BYTES,
            "identity relationship exceeds its replay byte bound"
        );
        Ok(())
    }

    /// Index only the candidate's staged relationships. Committed tokens are
    /// read from this store, and a later commit revalidates both directions.
    pub fn preview(
        &self,
        mut decision: IdentityDecision,
        previous: Option<&IdentityPreview>,
    ) -> Result<IdentityPreview> {
        if let Some(previous) = previous {
            let mut combined = previous.decision.clone();
            combined.merge(decision)?;
            decision = combined;
        }
        self.validate(&decision)?;
        let forward = decision
            .pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| (pair.source, index))
            .collect();
        Ok(IdentityPreview { decision, forward })
    }

    pub fn contains_pair(&self, case: &str, pair: IdentityPair) -> Result<bool> {
        self.contains_pair_in_scope(&IdentityScope::Case(case.into()), pair, None)
    }

    pub fn contains_pair_in_scope(
        &self,
        scope: &IdentityScope,
        pair: IdentityPair,
        preview: Option<&IdentityPreview>,
    ) -> Result<bool> {
        let pair = PreparedPair::prepare(pair)?;
        Ok(self
            .target(scope, &pair.source, preview)
            .is_some_and(|(target, _)| target == pair.target))
    }

    /// Recheck a previously validated delivery proposal against committed Session
    /// state. The producer has already validated the pairs as one proposal.
    pub fn prefetched_session_identity_is_current(&self, decision: &IdentityDecision) -> bool {
        let Some(limit) = self.session_limit else {
            return false;
        };
        if decision.scope != IdentityScope::Session {
            return false;
        }
        let bindings = self.scopes.get(&IdentityScope::Session);
        let mut new_entities = 0usize;
        let mut new_bytes = 0usize;
        for pair in &decision.pairs {
            if let Some((target, _)) = bindings.and_then(|scope| scope.forward.get(&pair.source)) {
                // The committed forward and reverse maps are always paired.
                if *target != pair.target {
                    return false;
                }
                continue;
            }
            if bindings.is_some_and(|scope| scope.reverse.contains_key(&pair.target)) {
                return false;
            }
            // Duplicates conservatively count against capacity on this path.
            new_entities += 1;
            new_bytes = new_bytes.saturating_add(pair.pair.target.len());
        }
        bindings.map_or(0, |scope| scope.entities) + new_entities <= limit
            && self.bytes.saturating_add(new_bytes) <= MAX_RUN_BYTES
    }

    /// Check that a prefetched decision only repeats permanent Session pairs.
    /// A compatible but absent pair still requires ordered live publication.
    pub fn prefetched_session_identity_is_committed(&self, decision: &IdentityDecision) -> bool {
        if self.session_limit.is_none() || decision.scope != IdentityScope::Session {
            return false;
        }
        let bindings = self.scopes.get(&IdentityScope::Session);
        decision.pairs.iter().all(|pair| {
            bindings
                .and_then(|scope| scope.forward.get(&pair.source))
                .is_some_and(|(target, _)| *target == pair.target)
        })
    }

    pub fn commit(&mut self, decision: IdentityDecision) -> Result<()> {
        self.validate(&decision)?;
        if decision.pairs.is_empty() {
            return Ok(());
        }
        let previous_entities = self.entities;
        let bindings = self.scopes.entry(decision.scope).or_default();
        for pair in decision.pairs {
            if bindings.forward.contains_key(&pair.source) {
                continue;
            }
            bindings.bytes += pair.pair.target.len();
            self.bytes += pair.pair.target.len();
            bindings
                .forward
                .insert(pair.source, (pair.target, pair.pair.target.into()));
            bindings.reverse.insert(pair.target, pair.source);
            bindings.entities += 1;
            self.entities += 1;
        }
        if self.entities != previous_entities {
            self.advance_revision();
        }
        Ok(())
    }

    /// A recorded read is an input. Known entities deliver their Target token;
    /// an unknown historical entity is fixed to its delivered Source value.
    pub fn deliveries(
        &self,
        case: &str,
        selected: &[PreparedIdentityDelivery],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        self.deliveries_in_scope(IdentityScope::Case(case.into()), selected, None)
    }

    pub fn deliveries_in_scope(
        &self,
        scope: IdentityScope,
        selected: &[PreparedIdentityDelivery],
        preview: Option<&IdentityPreview>,
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        scope.validate()?;
        ensure!(
            selected.len() <= MAX_PROPOSAL_PAIRS,
            "identity delivery proposal bound exceeded"
        );
        let mut values = Vec::with_capacity(selected.len());
        let mut pairs = Vec::with_capacity(selected.len());
        for selected in selected {
            let (target_hash, token) = self
                .target(&scope, &selected.source_hash, preview)
                .unwrap_or((selected.source_hash, selected.source.as_str()));
            let (value, pair) = selected.resolve(target_hash, token)?;
            values.push(value);
            pairs.push(pair);
        }
        let decision = IdentityDecision { scope, pairs };
        self.validate_with_preview(&decision, preview)?;
        Ok((values, decision))
    }

    /// Read only committed Session bindings, where a positive lookup is fixed
    /// for the duration of Replay. A missing binding must be resolved later.
    pub fn committed_session_delivery(
        &self,
        selected: Vec<PreparedIdentityDelivery>,
    ) -> Option<CommittedSessionDelivery> {
        let bindings = self.scopes.get(&IdentityScope::Session)?;
        let targets = selected
            .iter()
            .map(|identity| bindings.forward.get(&identity.source_hash).cloned())
            .collect::<Option<Vec<_>>>()?;
        Some(CommittedSessionDelivery { selected, targets })
    }

    fn target<'a>(
        &'a self,
        scope: &IdentityScope,
        source: &Fingerprint,
        preview: Option<&'a IdentityPreview>,
    ) -> Option<(Fingerprint, &'a str)> {
        self.scopes
            .get(scope)
            .and_then(|bindings| bindings.forward.get(source))
            .map(|(target, token)| (*target, token.as_ref()))
            .or_else(|| {
                preview
                    .filter(|preview| &preview.decision.scope == scope)?
                    .target(source)
            })
    }
}

/// An owned read of committed Session bindings. Typed validation and construction
/// of the proposal can run after the store guard has been released.
pub struct CommittedSessionDelivery {
    selected: Vec<PreparedIdentityDelivery>,
    targets: Vec<(Fingerprint, Box<str>)>,
}

impl CommittedSessionDelivery {
    pub fn resolve(self) -> Result<(Vec<Value>, IdentityDecision)> {
        ensure!(
            self.selected.len() <= MAX_PROPOSAL_PAIRS
                && self
                    .selected
                    .iter()
                    .zip(&self.targets)
                    .try_fold(0usize, |bytes, (source, (_, target))| {
                        bytes
                            .checked_add(source.source.len())?
                            .checked_add(target.len())
                    },)
                    .is_some_and(|bytes| bytes <= MAX_PROPOSAL_BYTES),
            "identity proposal bound exceeded"
        );
        let mut values = Vec::with_capacity(self.selected.len());
        let mut pairs = Vec::with_capacity(self.selected.len());
        for (source, (target_hash, token)) in self.selected.into_iter().zip(self.targets) {
            let (value, pair) = source.resolve(target_hash, &token)?;
            values.push(value);
            pairs.push(pair);
        }
        Ok((
            values,
            IdentityDecision {
                scope: IdentityScope::Session,
                pairs,
            },
        ))
    }
}

/// A complete Source value and an opaque validation policy supplied by its owner.
pub struct PreparedIdentityDelivery {
    source: String,
    source_hash: Fingerprint,
    policy: traffic_policy::PreparedPolicy,
}
impl PreparedIdentityDelivery {
    pub fn prepare(value: &Value, policy: traffic_policy::PreparedPolicy) -> Result<Self> {
        let source =
            super::key(value, "").map_err(|difference| anyhow::anyhow!(difference.reason))?;
        let prepared = Self {
            source_hash: Sha256::digest(source.as_bytes()).into(),
            source,
            policy,
        };
        prepared.validate(value)?;
        Ok(prepared)
    }
    fn validate(&self, value: &Value) -> Result<()> {
        let value = serde_json::from_value(value.clone())?;
        ensure!(
            self.policy.applies(&value, &traffic_value::Value::Null)?,
            "identity representation is invalid"
        );
        Ok(())
    }

    fn resolve(&self, target_hash: Fingerprint, token: &str) -> Result<(Value, PreparedPair)> {
        let value = serde_json::from_str(token).context("invalid typed identity delivery")?;
        self.validate(&value)?;
        Ok((
            value,
            PreparedPair {
                pair: IdentityPair {
                    source: self.source.clone(),
                    target: token.to_owned(),
                },
                source: self.source_hash,
                target: target_hash,
            },
        ))
    }
}

#[cfg(test)]
mod tests;
