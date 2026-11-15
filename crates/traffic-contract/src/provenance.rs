//! Bounded read provenance; only an actually delivered scalar pair permits a copy.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::rule::TimeContract;
use crate::time::ClockPair;

/// The host selects compiled rule scopes eligible for delivered-value provenance.
/// Storage and proof validation do not interpret policy implementation identities.
pub trait CopyRuleScope: Clone + Default + std::fmt::Debug + Send + Sync + 'static {
    fn permits(rule: &str) -> bool;
}

pub const MAX_CASE_COPIES: usize = 4096;
const MAX_TOTAL_COPIES: usize = 32768;
mod delivered;
pub use delivered::DeliveredTimeCopies;

pub trait PhysicalOrigin: Copy {
    fn fingerprint(self) -> [u8; 32];
}

fn scalar_hash(value: &Value) -> Option<[u8; 32]> {
    if !(value.is_number() || value.as_str().is_some_and(|text| text.len() <= 128)) {
        return None;
    }
    Some(Sha256::digest(serde_json::to_vec(value).ok()?).into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CopyKey {
    source_position: [u8; 32],
    target_position: [u8; 32],
    source_pattern: [u8; 32],
    target_pattern: [u8; 32],
    source: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct TimeCopyRecord {
    key: CopyKey,
    target: [u8; 32],
    scalar: Option<Value>,
    origin: CopyOrigin,
}
impl TimeCopyRecord {
    pub fn with_read(
        mut self,
        payload: [u8; 32],
        source_connection: Option<uuid::Uuid>,
        source_started: Option<chrono::DateTime<chrono::Utc>>,
        target_started: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        self.origin = CopyOrigin::Read {
            payload,
            source_connection,
            source_started,
            target_started,
        };
        self
    }

    pub fn with_write(
        mut self,
        payload: [u8; 32],
        source_connection: Option<uuid::Uuid>,
        source_started: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Self {
        self.origin = CopyOrigin::Write {
            payload,
            source_connection,
            source_started,
        };
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new(
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
    ) -> Result<Self> {
        let (Some(source), Some(target)) = (scalar_hash(source), scalar_hash(target)) else {
            anyhow::bail!("time copy requires bounded timestamp scalars");
        };
        Self::hashed(
            source_position,
            target_position,
            source_pattern,
            target_pattern,
            source,
            target,
        )
    }
    pub fn new_time(
        time: &TimeContract,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
    ) -> Result<Self> {
        let parsed = crate::compare::parse_time_pair(source, target, time)?;
        let mut record = Self::hashed(
            source_position,
            target_position,
            source_pattern,
            target_pattern,
            parsed_hash(source, parsed.0),
            parsed_hash(target, parsed.1),
        )?;
        if scalar_hash(target).is_some() {
            record.scalar = Some(target.clone());
        }
        Ok(record)
    }
    fn hashed(
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: [u8; 32],
        target: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            source_pattern.len() <= 1024 && target_pattern.len() <= 1024,
            "time copy identity exceeds its bound"
        );
        Ok(Self {
            key: copy_key(
                source_position,
                target_position,
                source_pattern,
                target_pattern,
                source,
            ),
            target,
            scalar: None,
            origin: CopyOrigin::Other,
        })
    }
}
fn time_hash(value: &Value, time: &TimeContract) -> Result<[u8; 32]> {
    Ok(parsed_hash(
        value,
        crate::compare::parse_time_value(value, time)?,
    ))
}
fn parsed_hash(value: &Value, parsed: i128) -> [u8; 32] {
    let category = if value.is_string() {
        0
    } else {
        1 | u8::from(value.is_i64()) << 1
            | u8::from(value.is_u64()) << 2
            | u8::from(value.is_f64()) << 3
    };
    let mut hash = Sha256::new();
    hash.update(b"traffic/typed-time/v1\0");
    hash.update([category]);
    hash.update(parsed.to_be_bytes());
    hash.finalize().into()
}
fn copy_key(
    source_position: impl PhysicalOrigin,
    target_position: impl PhysicalOrigin,
    source_pattern: &str,
    target_pattern: &str,
    source: [u8; 32],
) -> CopyKey {
    CopyKey {
        source_position: source_position.fingerprint(),
        target_position: target_position.fingerprint(),
        source_pattern: Sha256::digest(source_pattern.as_bytes()).into(),
        target_pattern: Sha256::digest(target_pattern.as_bytes()).into(),
        source,
    }
}

/// Timestamp parsing and physical identity hashing happen before a store lock.
pub struct TimeCopyLookup<S: CopyRuleScope> {
    _scope: std::marker::PhantomData<S>,
    key: CopyKey,
    rule_id: String,
    source_pointer: String,
    target_pattern: String,
    typed: bool,
    stored_read: Option<StoredRead>,
}

struct StoredRead {
    payload: [u8; 32],
    source_connection: Option<uuid::Uuid>,
    completed: chrono::DateTime<chrono::Utc>,
}

impl<S: CopyRuleScope> TimeCopyLookup<S> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_time(
        time: &TimeContract,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<Self> {
        if !S::permits(rule_id) {
            return None;
        }
        Some(Self {
            _scope: std::marker::PhantomData,
            key: copy_key(
                source_position,
                target_position,
                source_pattern,
                target_pattern,
                time_hash(source, time).ok()?,
            ),
            rule_id: rule_id.into(),
            source_pointer: source_pattern.into(),
            target_pattern: target_pattern.into(),
            typed: true,
            stored_read: None,
        })
    }
    pub fn at(mut self, source_pointer: &str, target_pattern: &str) -> Self {
        self.source_pointer = source_pointer.into();
        self.target_pattern = target_pattern.into();
        self
    }

    pub fn with_read(
        mut self,
        payload: [u8; 32],
        source_connection: Option<uuid::Uuid>,
        completed: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        self.stored_read = Some(StoredRead {
            payload,
            source_connection,
            completed,
        });
        self
    }
}

#[derive(Default)]
pub struct TimeCopyStore<S: CopyRuleScope> {
    _scope: std::marker::PhantomData<S>,
    cases: BTreeMap<String, CaseCopies>,
    total: usize,
    record_clocks: ClockPair,
    lookup_clocks: ClockPair,
}

#[derive(Default)]
struct CaseCopies {
    entries: BTreeMap<CopyKey, CopyValue>,
    total: usize,
}
#[derive(Clone)]
struct CopyValue {
    target: Option<[u8; 32]>,
    scalar: Option<Value>,
    deliveries: Vec<CopyDelivery>,
    // Proof lookup can drop redundant deliveries, but supersession must
    // account for every read that observed the current counterpart.
    latest_read_start: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Copy)]
struct CopyDelivery {
    clocks: (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
    origin: CopyOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CopyOrigin {
    Other,
    Read {
        payload: [u8; 32],
        source_connection: Option<uuid::Uuid>,
        source_started: Option<chrono::DateTime<chrono::Utc>>,
        target_started: Option<chrono::DateTime<chrono::Utc>>,
    },
    Write {
        payload: [u8; 32],
        source_connection: Option<uuid::Uuid>,
        source_started: Option<chrono::DateTime<chrono::Utc>>,
    },
}

impl CopyDelivery {
    fn dominates(self, other: Self) -> bool {
        if self.clocks.0 > other.clocks.0 || self.clocks.1 > other.clocks.1 {
            return false;
        }
        match (self.origin, other.origin) {
            (
                CopyOrigin::Read {
                    payload,
                    source_connection,
                    source_started,
                    ..
                },
                CopyOrigin::Read {
                    payload: other_payload,
                    source_connection: other_source_connection,
                    source_started: other_source_started,
                    ..
                },
            ) => {
                payload == other_payload
                    && source_connection == other_source_connection
                    && (source_started == other_source_started
                        || source_started
                            .zip(other_source_started)
                            .is_some_and(|(start, other_start)| start <= other_start))
            }
            (left, right) => left == right,
        }
    }

    fn read_start(self) -> Option<chrono::DateTime<chrono::Utc>> {
        match self.origin {
            CopyOrigin::Read { target_started, .. } => {
                Some(target_started.unwrap_or(self.clocks.1))
            }
            _ => None,
        }
    }

    fn write_precedes_read_on_source(self, read: Self) -> bool {
        let CopyOrigin::Read {
            payload,
            source_connection,
            source_started: Some(read_started),
            ..
        } = read.origin
        else {
            return false;
        };
        self.write_visible_in_source_read(payload, source_connection, read_started, read.clocks.0)
    }

    fn write_visible_in_source_read(
        self,
        read_payload: [u8; 32],
        read_connection: Option<uuid::Uuid>,
        read_started: chrono::DateTime<chrono::Utc>,
        read_completed: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        // An adapter supplies authenticated reads and writes of the same stored
        // payload. Across sockets an overlapping read must observe those bytes,
        // start after the write started, and finish after its reply completed.
        matches!(
            self.origin,
            CopyOrigin::Write { payload, source_connection, source_started }
                if payload == read_payload
                    && (self.clocks.0 <= read_started
                        || source_connection.zip(read_connection).is_some_and(|(write, read)| write != read)
                            && source_started.is_some_and(|start| start <= read_started
                                && self.clocks.0 <= read_completed))
        )
    }
}
impl CopyValue {
    fn cost(&self) -> usize {
        self.deliveries.len().max(1)
    }
    fn observe(&mut self, target: [u8; 32], scalar: Option<Value>, delivery: CopyDelivery) {
        if self.target != Some(target) {
            if !self.deliveries.is_empty() {
                // An early replayed GET of this exact Source value supplied a
                // derived timestamp. Once its real SET completes, use the
                // timestamp that Target wrote for subsequent reads.
                if self
                    .latest_read_start
                    .is_some_and(|start| start < delivery.clocks.1)
                    && self
                        .deliveries
                        .iter()
                        .all(|read| delivery.write_precedes_read_on_source(*read))
                {
                    self.target = Some(target);
                    self.scalar = scalar;
                    self.deliveries.clear();
                    self.deliveries.push(delivery);
                    self.latest_read_start = None;
                    return;
                }
                if let Some(start) = delivery.read_start()
                    && self.deliveries.iter().all(|write| {
                        start < write.clocks.1 && write.write_precedes_read_on_source(delivery)
                    })
                {
                    return;
                }
            }
            self.target = None;
            self.scalar = None;
            self.deliveries.clear();
            self.latest_read_start = None;
            return;
        }
        if self.scalar.is_none() {
            self.scalar = scalar;
        }
        self.latest_read_start = self.latest_read_start.max(delivery.read_start());
        // Keep real paired observations; independent minima can invent a read
        // that preceded the write in both executions when none actually did.
        if self
            .deliveries
            .iter()
            .any(|existing| existing.dominates(delivery))
        {
            return;
        }
        self.deliveries
            .retain(|existing| !delivery.dominates(*existing));
        self.deliveries.push(delivery);
    }
}

/// Constructed by the read-provenance store; intentionally contains no payload.
#[derive(Clone, Debug)]
pub struct VerifiedTimeCopy<S: CopyRuleScope> {
    _scope: std::marker::PhantomData<S>,
    rule_id: String,
    source_pointer: String,
    target_pattern: String,
    source: [u8; 32],
    target: [u8; 32],
    typed: bool,
}

impl<S: CopyRuleScope> VerifiedTimeCopy<S> {
    pub fn permits_value(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        time: &TimeContract,
    ) -> bool {
        self.permits(rule, source_pointer, target_pointer, source, target, time)
    }
    pub fn scope(&self) -> (&str, &str) {
        (&self.rule_id, &self.source_pointer)
    }
    /// SQL adapters prefix the physical field's logical path with its current
    /// comparison slot. The authenticated scalar pair remains immutable.
    #[cfg(any(test, feature = "test-support"))]
    pub fn at(mut self, source_pointer: &str, target_pattern: &str) -> Self {
        self.source_pointer = source_pointer.into();
        self.target_pattern = target_pattern.into();
        self
    }
    pub fn permits(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        time: &TimeContract,
    ) -> bool {
        S::permits(rule)
            && rule == self.rule_id
            && source_pointer == self.source_pointer
            && self.target_pattern.split('/').count() == target_pointer.split('/').count()
            && self
                .target_pattern
                .split('/')
                .zip(target_pointer.split('/'))
                .all(|(a, b)| a == "*" || a == b)
            && (if self.typed {
                time_hash(source, time).ok()
            } else {
                scalar_hash(source)
            }) == Some(self.source)
            && (if self.typed {
                time_hash(target, time).ok()
            } else {
                scalar_hash(target)
            }) == Some(self.target)
    }
}

impl<S: CopyRuleScope> TimeCopyStore<S> {
    pub fn has_case(&self, case: &str) -> bool {
        self.cases
            .get(case)
            .is_some_and(|case| !case.entries.is_empty())
    }
    pub fn set_record_clocks(&mut self, clocks: ClockPair) {
        self.record_clocks = clocks;
    }
    pub fn set_lookup_clocks(&mut self, clocks: ClockPair) {
        self.lookup_clocks = clocks;
    }
    pub fn begin_case(&mut self, case: &str) {
        if let Some(old) = self.cases.remove(case) {
            self.total -= old.total;
        }
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn record(
        &mut self,
        case: &str,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
    ) -> Result<()> {
        self.record_batch(
            case,
            vec![TimeCopyRecord::new(
                source_position,
                target_position,
                source_pattern,
                target_pattern,
                source,
                target,
            )?],
        )
    }
    pub fn record_batch(&mut self, case: &str, records: Vec<TimeCopyRecord>) -> Result<()> {
        ensure!(
            case.len() <= 1024 && records.len() <= MAX_CASE_COPIES,
            "time copy batch exceeds its bound"
        );
        if records.is_empty() {
            return Ok(());
        }
        let Ok(delivery) = self.record_clocks.require() else {
            return Ok(());
        };
        let old = self.cases.get(case);
        // Stage only this read's touched entries. Capacity failure publishes
        // neither partial mappings nor partial ambiguity changes.
        let mut staged = BTreeMap::<CopyKey, CopyValue>::new();
        for record in records {
            staged
                .entry(record.key)
                .or_insert_with(|| {
                    old.and_then(|case| case.entries.get(&record.key))
                        .cloned()
                        .unwrap_or(CopyValue {
                            target: Some(record.target),
                            scalar: record.scalar.clone(),
                            deliveries: vec![],
                            latest_read_start: None,
                        })
                })
                .observe(
                    record.target,
                    record.scalar,
                    CopyDelivery {
                        clocks: delivery,
                        origin: record.origin,
                    },
                );
        }
        let removed = staged
            .keys()
            .filter_map(|key| old?.entries.get(key))
            .map(CopyValue::cost)
            .sum::<usize>();
        let added = staged.values().map(CopyValue::cost).sum::<usize>();
        let case_total = old.map_or(0, |case| case.total) - removed + added;
        let total = self.total - removed + added;
        ensure!(
            case_total <= MAX_CASE_COPIES && total <= MAX_TOTAL_COPIES,
            "delivered time provenance exceeds its bounded capacity"
        );
        let case = self.cases.entry(case.into()).or_default();
        case.entries.extend(staged);
        case.total = case_total;
        self.total = total;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn proof_for_source(
        &self,
        case: &str,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy<S>> {
        if !S::permits(rule_id) {
            return None;
        }
        let source = scalar_hash(source)?;
        self.proof_prepared(
            case,
            &TimeCopyLookup {
                _scope: std::marker::PhantomData,
                key: copy_key(
                    source_position,
                    target_position,
                    source_pattern,
                    target_pattern,
                    source,
                ),
                rule_id: rule_id.into(),
                source_pointer: source_pattern.into(),
                target_pattern: target_pattern.into(),
                typed: false,
                stored_read: None,
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn proof_for_source_time(
        &self,
        time: &TimeContract,
        case: &str,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy<S>> {
        self.proof_prepared(
            case,
            &TimeCopyLookup::new_time(
                time,
                source_position,
                target_position,
                source_pattern,
                target_pattern,
                source,
                rule_id,
            )?,
        )
    }
    pub fn proof_prepared(
        &self,
        case: &str,
        lookup: &TimeCopyLookup<S>,
    ) -> Option<VerifiedTimeCopy<S>> {
        let cutoff = self.lookup_clocks.require().ok()?;
        let value = self.cases.get(case)?.entries.get(&lookup.key)?;
        if !value.deliveries.iter().any(|delivery| {
            let (source, target) = delivery.clocks;
            target <= cutoff.1
                && (source <= cutoff.0
                    // Overlapping reads can observe the same stored value.
                    // The same bytes must link either a completed read or a
                    // write that had taken effect before this read completed.
                    || lookup.stored_read.as_ref().is_some_and(|read| {
                        (matches!(delivery.origin, CopyOrigin::Read { payload, .. } if payload == read.payload)
                            && source <= read.completed)
                            || delivery.write_visible_in_source_read(
                                read.payload, read.source_connection, cutoff.0, read.completed,
                            )
                    }))
        }) {
            return None;
        }
        let target = value.target?;
        Some(VerifiedTimeCopy {
            _scope: std::marker::PhantomData,
            rule_id: lookup.rule_id.clone(),
            source_pointer: lookup.source_pointer.clone(),
            target_pattern: lookup.target_pattern.clone(),
            source: lookup.key.source,
            target,
            typed: lookup.typed,
        })
    }
    /// A known stored timestamp is reused only after the same paired observation
    /// precedes this request in both executions. Ambiguity never invents a value.
    pub fn delivery_prepared(
        &self,
        case: &str,
        lookup: &TimeCopyLookup<S>,
    ) -> Result<Option<(Value, VerifiedTimeCopy<S>)>> {
        let Some(value) = self
            .cases
            .get(case)
            .and_then(|case| case.entries.get(&lookup.key))
        else {
            return Ok(None);
        };
        let proof = self.proof_prepared(case, lookup).ok_or_else(|| {
            anyhow::anyhow!("stored timestamp has ambiguous or unavailable causal provenance")
        })?;
        Ok(value.scalar.clone().map(|scalar| (scalar, proof)))
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn proof(
        &self,
        case: &str,
        source_position: impl PhysicalOrigin,
        target_position: impl PhysicalOrigin,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy<S>> {
        let proof = self.proof_for_source(
            case,
            source_position,
            target_position,
            source_pattern,
            target_pattern,
            source,
            rule_id,
        )?;
        (scalar_hash(target) == Some(proof.target)).then_some(proof)
    }
}

impl<S: CopyRuleScope> TimeCopyStore<S> {
    #[cfg(any(test, feature = "test-support"))]
    pub fn retained_count(&self) -> usize {
        self.total
    }
}
#[derive(Debug, Clone)]
pub struct TimeCopyLeaf {
    pub rule_id: &'static str,
    pub pattern: String,
    pub pointer: String,
    pub value: Value,
    pub time: TimeContract,
}

impl<S: CopyRuleScope> crate::compare::TimeCopyProof for VerifiedTimeCopy<S> {
    fn scope(&self) -> (&str, &str) {
        self.scope()
    }
    fn permits_value(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        requirement: &traffic_value::Value,
    ) -> bool {
        serde_json::to_value(requirement)
            .ok()
            .and_then(|value| serde_json::from_value::<TimeContract>(value).ok())
            .is_some_and(|time| {
                self.permits_value(rule, source_pointer, target_pointer, source, target, &time)
            })
    }
}

#[cfg(test)]
mod tests;
