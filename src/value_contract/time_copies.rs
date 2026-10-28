//! Bounded read provenance; only an actually delivered scalar pair permits a copy.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::time::ClockPair;
use crate::policy::{RedisContainer, TimeContract};

const MAX_CASE_COPIES: usize = 4096;
const MAX_TOTAL_COPIES: usize = 32768;
mod response;
pub(crate) use response::ResponseTimeCopies;

#[derive(Clone, Copy)]
pub(crate) enum TimeCopyPosition<'a> {
    Http {
        host: &'a str,
        port: u16,
        exchange: &'a str,
    },
    Mysql {
        host: &'a str,
        port: u16,
        database: &'a str,
        table: &'a str,
        column: &'a str,
    },
    Redis {
        host: &'a str,
        port: u16,
        database: i64,
        key: &'a [u8],
        container: RedisContainer,
        hash_field: Option<&'a [u8]>,
    },
}

impl TimeCopyPosition<'_> {
    fn fingerprint(self) -> [u8; 32] {
        fn part(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        let mut hash = Sha256::new();
        hash.update(b"traffic/time-copy-position/v1\0");
        match self {
            Self::Http {
                host,
                port,
                exchange,
            } => {
                part(&mut hash, b"http");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, exchange.as_bytes());
            }
            Self::Mysql {
                host,
                port,
                database,
                table,
                column,
            } => {
                part(&mut hash, b"mysql");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, database.as_bytes());
                part(&mut hash, table.as_bytes());
                part(&mut hash, column.to_ascii_lowercase().as_bytes());
            }
            Self::Redis {
                host,
                port,
                database,
                key,
                container,
                hash_field,
            } => {
                part(&mut hash, b"redis");
                part(&mut hash, host.to_ascii_lowercase().as_bytes());
                part(&mut hash, &port.to_be_bytes());
                part(&mut hash, &database.to_be_bytes());
                part(&mut hash, key);
                part(
                    &mut hash,
                    &[match container {
                        RedisContainer::String => 0,
                        RedisContainer::Hash => 1,
                        RedisContainer::List => 2,
                    }],
                );
                part(&mut hash, &[u8::from(hash_field.is_some())]);
                part(&mut hash, hash_field.unwrap_or_default());
            }
        }
        hash.finalize().into()
    }
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
pub(crate) struct TimeCopyRecord {
    key: CopyKey,
    target: [u8; 32],
    scalar: Option<Value>,
}
impl TimeCopyRecord {
    #[cfg(test)]
    pub(crate) fn new(
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
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
    pub(crate) fn new_time(
        time: &TimeContract,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
    ) -> Result<Self> {
        let parsed = super::json::parse_time_pair(source, target, time)?;
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
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
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
        })
    }
}
fn time_hash(value: &Value, time: &TimeContract) -> Result<[u8; 32]> {
    Ok(parsed_hash(
        value,
        super::json::parse_time_value(value, time)?,
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
    source_position: TimeCopyPosition<'_>,
    target_position: TimeCopyPosition<'_>,
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
pub(crate) struct TimeCopyLookup {
    key: CopyKey,
    rule_id: String,
    source_pointer: String,
    target_pattern: String,
    typed: bool,
}

impl TimeCopyLookup {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_time(
        time: &TimeContract,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<Self> {
        if !schema_rule(rule_id) {
            return None;
        }
        Some(Self {
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
        })
    }
    pub(crate) fn at(mut self, source_pointer: &str, target_pattern: &str) -> Self {
        self.source_pointer = source_pointer.into();
        self.target_pattern = target_pattern.into();
        self
    }
}

#[derive(Default)]
pub(crate) struct TimeCopyStore {
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
    deliveries: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}
impl CopyValue {
    fn cost(&self) -> usize {
        self.deliveries.len().max(1)
    }
    fn observe(
        &mut self,
        target: [u8; 32],
        scalar: Option<Value>,
        delivery: (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>),
    ) {
        if self.target != Some(target) {
            self.target = None;
            self.scalar = None;
            self.deliveries.clear();
            return;
        }
        if self.scalar.is_none() {
            self.scalar = scalar;
        }
        // Keep real paired observations; independent minima can invent a read
        // that preceded the write in both executions when none actually did.
        if self
            .deliveries
            .iter()
            .any(|&(source, target)| source <= delivery.0 && target <= delivery.1)
        {
            return;
        }
        self.deliveries
            .retain(|&(source, target)| delivery.0 > source || delivery.1 > target);
        self.deliveries.push(delivery);
    }
}

/// Constructed by the read-provenance store; intentionally contains no payload.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedTimeCopy {
    rule_id: String,
    source_pointer: String,
    target_pattern: String,
    source: [u8; 32],
    target: [u8; 32],
    typed: bool,
}

impl VerifiedTimeCopy {
    pub(crate) fn permits_value(
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
    pub(super) fn scope(&self) -> (&str, &str) {
        (&self.rule_id, &self.source_pointer)
    }
    /// SQL adapters prefix the physical field's logical path with its current
    /// comparison slot. The authenticated scalar pair remains immutable.
    #[cfg(test)]
    pub(crate) fn at(mut self, source_pointer: &str, target_pattern: &str) -> Self {
        self.source_pointer = source_pointer.into();
        self.target_pattern = target_pattern.into();
        self
    }
    pub(super) fn permits(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        time: &TimeContract,
    ) -> bool {
        schema_rule(rule)
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

impl TimeCopyStore {
    pub(crate) fn has_case(&self, case: &str) -> bool {
        self.cases
            .get(case)
            .is_some_and(|case| !case.entries.is_empty())
    }
    pub(crate) fn set_record_clocks(&mut self, clocks: ClockPair) {
        self.record_clocks = clocks;
    }
    pub(crate) fn set_lookup_clocks(&mut self, clocks: ClockPair) {
        self.lookup_clocks = clocks;
    }
    pub(crate) fn begin_case(&mut self, case: &str) {
        if let Some(old) = self.cases.remove(case) {
            self.total -= old.total;
        }
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn record(
        &mut self,
        case: &str,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
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
    pub(crate) fn record_batch(&mut self, case: &str, records: Vec<TimeCopyRecord>) -> Result<()> {
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
                        })
                })
                .observe(record.target, record.scalar, delivery);
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
    #[cfg(test)]
    pub(crate) fn proof_for_source(
        &self,
        case: &str,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy> {
        if !schema_rule(rule_id) {
            return None;
        }
        let source = scalar_hash(source)?;
        self.proof_prepared(
            case,
            &TimeCopyLookup {
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
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn proof_for_source_time(
        &self,
        time: &TimeContract,
        case: &str,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy> {
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
    pub(crate) fn proof_prepared(
        &self,
        case: &str,
        lookup: &TimeCopyLookup,
    ) -> Option<VerifiedTimeCopy> {
        let cutoff = self.lookup_clocks.require().ok()?;
        let value = self.cases.get(case)?.entries.get(&lookup.key)?;
        if !value
            .deliveries
            .iter()
            .any(|&(source, target)| source <= cutoff.0 && target <= cutoff.1)
        {
            return None;
        }
        let target = value.target?;
        Some(VerifiedTimeCopy {
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
    pub(crate) fn delivery_prepared(
        &self,
        case: &str,
        lookup: &TimeCopyLookup,
    ) -> Result<Option<(Value, VerifiedTimeCopy)>> {
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
    #[cfg(test)]
    pub(crate) fn proof(
        &self,
        case: &str,
        source_position: TimeCopyPosition<'_>,
        target_position: TimeCopyPosition<'_>,
        source_pattern: &str,
        target_pattern: &str,
        source: &Value,
        target: &Value,
        rule_id: &str,
    ) -> Option<VerifiedTimeCopy> {
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

pub(crate) fn schema_rule(id: &str) -> bool {
    id == crate::policy::GLOBAL_JSON_ID || id == "global.mysql" || id == "global.redis"
}

#[derive(Debug, Clone)]
pub(crate) struct TimeCopyLeaf {
    pub(crate) pattern: String,
    pub(crate) pointer: String,
    pub(crate) value: Value,
    pub(crate) time: TimeContract,
}

/// Source chooses each global format; retain the authored pointer pattern so
/// equal stored values can be copied through independently shaped carriers.
pub(crate) fn global_leaves(
    root: &Value,
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: super::json::AnchorClocks,
) -> Result<Vec<TimeCopyLeaf>> {
    let mut output = Vec::new();
    for (pattern, field) in &plan.fields {
        if !matches!(field, crate::policy::GlobalField::Time { .. }) {
            continue;
        }
        for pointer in super::delivery::select(pattern, root)? {
            let Some(value) = root.pointer(&pointer) else {
                continue;
            };
            let selected = field.select_contract_with_clock(
                value,
                clocks.dependency.source.or(clocks.case.source),
            )?;
            let Some(time) = selected.time() else {
                continue;
            };
            super::json::parse_time_pair(value, value, &time)?;
            output.push(TimeCopyLeaf {
                pattern: pattern.clone(),
                pointer,
                value: value.clone(),
                time,
            });
            ensure!(
                output.len() <= MAX_CASE_COPIES,
                "global time copy leaf enumeration exceeds its bound"
            );
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
