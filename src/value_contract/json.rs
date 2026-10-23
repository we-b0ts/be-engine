//! Pure, bounded comparison of a decoded value. Protocol admission and commits
//! remain with the caller. Selected fields compose before the strict remainder.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use super::time::{self, ClockPair, TimeError};
use crate::policy::{FieldContract, TimeAnchor, TimeRelation, TimestampFormat};
mod clock_scope;
pub(crate) mod diagnosis;
mod identity;
mod native;
pub(crate) use native::{LeafContext, LeafObservations, NativeField, NonceIdentity, VerifiedField};

const MAX_COMPARISONS: usize = 16_384;
const MAX_DEPTH: usize = 128;

type TimeRelationships =
    BTreeMap<(TimeAnchor, Option<String>, clock_scope::ScopeKey), Vec<(i128, i128)>>;
const MAX_TIME_OBSERVATIONS: usize = 4096;
fn time_observation_count(
    relationships: &TimeRelationships,
    key: &(TimeAnchor, Option<String>, clock_scope::ScopeKey),
) -> usize {
    if key.2.is_shared() {
        relationships.get(key).map_or(0, Vec::len)
    } else {
        relationships
            .iter()
            .filter(|((_, _, scope), _)| !scope.is_shared())
            .map(|(_, times)| times.len())
            .sum()
    }
}
type NonceRelationships = BTreeMap<(String, String), Vec<([u8; 32], [u8; 32])>>;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AnchorClocks {
    pub(crate) case: ClockPair,
    pub(crate) dependency: ClockPair,
    pub(crate) delivery: ClockPair,
}

impl AnchorClocks {
    fn get(self, anchor: TimeAnchor) -> ClockPair {
        match anchor {
            TimeAnchor::DependencyRequestStart => self.dependency,
            TimeAnchor::ApiRequestStart | TimeAnchor::DependencyDelivery => ClockPair::default(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Field<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) pointer: &'a str,
    pub(crate) contract: &'a FieldContract,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct Difference {
    pub(crate) pointer: String,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Comparison {
    pub(crate) evaluated: BTreeSet<String>,
    pub(crate) time_validations: BTreeMap<String, usize>,
    pub(crate) differences: Vec<Difference>,
    #[serde(skip)]
    pub(crate) relationships: TimeRelationships,
    #[serde(skip)]
    pub(crate) nonce_relationships: NonceRelationships,
    #[serde(skip)]
    pub(crate) identities: BTreeMap<String, identity::Bijection>,
}

impl Comparison {
    pub(crate) fn passed(&self) -> bool {
        self.differences.is_empty()
    }
    pub(crate) fn merge_and_validate(&mut self, other: Comparison) {
        for (binding, identities) in other.identities {
            if let Err(reason) = self
                .identities
                .entry(binding)
                .or_default()
                .merge(identities)
            {
                self.differences.push(difference("", reason));
            }
        }
        self.evaluated.extend(other.evaluated);
        self.differences.extend(other.differences);
        for (rule_id, count) in other.time_validations {
            *self.time_validations.entry(rule_id).or_default() += count;
        }
        for (scope, values) in other.relationships {
            let mut observations = time_observation_count(&self.relationships, &scope);
            if !scope.2.is_shared()
                && !self.relationships.contains_key(&scope)
                && observations >= MAX_TIME_OBSERVATIONS
            {
                self.differences.push(difference(
                    "",
                    "scoped time relationship exceeds 4096 distinct observations",
                ));
                break;
            }
            let existing = self.relationships.entry(scope).or_default();
            for pair in values {
                if existing.contains(&pair) {
                    continue;
                }
                if observations >= MAX_TIME_OBSERVATIONS {
                    self.differences.push(difference(
                        "",
                        "time relationship exceeds 4096 distinct observations",
                    ));
                    break;
                }
                if let Some(error) = existing
                    .iter()
                    .find_map(|other| time::validate_relationships(&[*other, pair]).err())
                {
                    self.differences.push(difference("", &error.to_string()));
                }
                existing.push(pair);
                observations += 1;
            }
        }
        for (scope, pairs) in other.nonce_relationships {
            let existing = self.nonce_relationships.entry(scope).or_default();
            for (source, target) in pairs {
                if existing
                    .iter()
                    .any(|(a, b)| (*a == source && *b != target) || (*b == target && *a != source))
                {
                    self.differences
                        .push(difference("", "generated binding bijection changed"));
                }
                if !existing.contains(&(source, target)) {
                    existing.push((source, target));
                }
            }
        }
    }
}

#[derive(Clone, Default)]
struct Decisions {
    evaluated: BTreeSet<String>,
    selected: BTreeSet<usize>,
    selected_native: BTreeSet<usize>,
    times: TimeRelationships,
    time_validations: BTreeMap<String, usize>,
    nonces: NonceRelationships,
    identities: BTreeMap<String, identity::Bijection>,
}

struct MultisetSlice<'a> {
    source: &'a [Value],
    target: &'a [Value],
    source_pointer: &'a str,
    target_pointer: &'a str,
    depth: usize,
}

struct Comparator<'a> {
    fields: &'a [Field<'a>],
    native: &'a [NativeField<'a>],
    verified: &'a [VerifiedField<'a>],
    clocks: AnchorClocks,
    remaining: usize,
    source_root: &'a Value,
    target_root: &'a Value,
}

pub(crate) fn compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_native(source, target, fields, &[], clocks)
}

pub(crate) fn compare_with_native(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    compare_with_verified(source, target, fields, native, &[], clocks)
}

pub(crate) fn compare_with_verified(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    native: &[NativeField<'_>],
    verified: &[VerifiedField<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    let mut comparator = Comparator {
        fields,
        native,
        verified,
        clocks,
        remaining: MAX_COMPARISONS,
        source_root: source,
        target_root: target,
    };
    let mut decisions = Decisions::default();
    let result = comparator
        .node(source, target, "", "", &mut decisions, 0)
        .and_then(|()| {
            if let Some(missing) = fields.iter().enumerate().find(|(index, field)| {
                !decisions.selected.contains(index) && pointer_observed(source, field.pointer)
            }) {
                return Err(difference(
                    missing.1.pointer,
                    "selected field was not observed",
                ));
            }
            if let Some((_, missing)) = native
                .iter()
                .map(|field| field.pointer)
                .chain(verified.iter().map(|field| field.pointer))
                .enumerate()
                .find(|(index, pointer)| {
                    !decisions.selected_native.contains(index) && pointer_observed(source, pointer)
                })
            {
                return Err(difference(
                    missing,
                    "selected native field was not observed",
                ));
            }
            validate_relationships(&decisions).map_err(|e| difference("", &e.to_string()))
        });
    Comparison {
        evaluated: decisions.evaluated,
        time_validations: decisions.time_validations,
        differences: result.err().into_iter().collect(),
        relationships: decisions.times,
        nonce_relationships: decisions.nonces,
        identities: decisions.identities,
    }
}

fn difference(pointer: &str, reason: &str) -> Difference {
    Difference {
        pointer: pointer.into(),
        reason: reason.into(),
    }
}

/// A Source shape with no selected leaf leaves the entire value exact.
pub(crate) fn pointer_observed(root: &Value, pattern: &str) -> bool {
    fn visit(root: &Value, segments: &[&str]) -> bool {
        let Some((segment, rest)) = segments.split_first() else {
            return true;
        };
        if *segment == "*" {
            root.as_array()
                .is_some_and(|values| values.iter().any(|value| visit(value, rest)))
        } else {
            root.pointer(&format!("/{segment}"))
                .is_some_and(|value| visit(value, rest))
        }
    }
    visit(root, &pattern.split('/').skip(1).collect::<Vec<_>>())
}

fn pointer_matches(pattern: &str, pointer: &str, root: &Value) -> bool {
    if pattern.split('/').count() != pointer.split('/').count() {
        return false;
    }
    let mut parent = Some(root);
    for (a, b) in pattern.split('/').skip(1).zip(pointer.split('/').skip(1)) {
        if a != b
            && !(a == "*"
                && parent.is_some_and(Value::is_array)
                && b.parse::<usize>().is_ok()
                && (b == "0" || !b.starts_with('0')))
        {
            return false;
        }
        parent = parent.and_then(|parent| parent.pointer(&format!("/{b}")));
    }
    true
}

fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_relationships(decisions: &Decisions) -> Result<(), TimeError> {
    for times in decisions.times.values() {
        time::validate_relationships(times)?;
    }
    Ok(())
}

impl Comparator<'_> {
    fn node(
        &mut self,
        source: &Value,
        target: &Value,
        pointer: &str,
        target_pointer: &str,
        decisions: &mut Decisions,
        depth: usize,
    ) -> Result<(), Difference> {
        if depth > MAX_DEPTH || self.remaining == 0 {
            return Err(difference(pointer, "contract comparison limit exceeded"));
        }
        self.remaining -= 1;
        let selected = self
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| pointer_matches(f.pointer, pointer, self.source_root))
            .collect::<Vec<_>>();
        let native = self
            .native
            .iter()
            .enumerate()
            .filter(|(_, field)| pointer_matches(field.pointer, pointer, self.source_root))
            .collect::<Vec<_>>();
        let verified = self
            .verified
            .iter()
            .enumerate()
            .filter(|(_, field)| pointer_matches(field.pointer, pointer, self.source_root))
            .collect::<Vec<_>>();
        if selected.len() + native.len() + verified.len() > 1 {
            return Err(difference(pointer, "conflicting field contracts"));
        }
        if let Some((index, field)) = verified.first() {
            decisions.selected_native.insert(self.native.len() + *index);
            decisions.evaluated.insert(field.rule_id.into());
            return native::verify(
                field,
                LeafContext {
                    source,
                    target,
                    source_pointer: pointer,
                    target_pointer,
                    source_root: self.source_root,
                    target_root: self.target_root,
                    clocks: self.clocks,
                },
                decisions,
            );
        }
        if let Some((index, field)) = native.first() {
            decisions.selected_native.insert(*index);
            decisions.evaluated.insert(field.rule_id.into());
            return native::compare(source, target, field, pointer, self.clocks, decisions);
        }
        if let Some((index, field)) = selected.first() {
            decisions.selected.insert(*index);
            decisions.evaluated.insert(field.rule_id.into());
            let contract = if let FieldContract::Conditional { when, contract } = field.contract {
                if !when
                    .matches_pair(self.source_root, self.target_root, pointer, target_pointer)
                    .map_err(|_| {
                        difference(
                            pointer,
                            "field condition is absent, invalid, or changed on Target",
                        )
                    })?
                {
                    return if source == target {
                        Ok(())
                    } else {
                        Err(difference(
                            pointer,
                            "inactive field contract requires exact equality",
                        ))
                    };
                }
                contract.as_ref()
            } else {
                field.contract
            };
            match contract {
                FieldContract::Identity {
                    binding,
                    prefix,
                    format,
                } => {
                    return identity::compare(
                        source, target, binding, prefix, *format, pointer, decisions,
                    );
                }
                FieldContract::Conditional { .. } => {
                    return Err(difference(
                        pointer,
                        "nested field conditions are unsupported",
                    ));
                }
                FieldContract::Unordered => {
                    let (Some(source), Some(target)) = (source.as_array(), target.as_array())
                    else {
                        return Err(difference(pointer, "unordered requires two arrays"));
                    };
                    if source.len() != target.len() {
                        return Err(difference(pointer, "array cardinality changed"));
                    }
                    let parent_segments = pointer.split('/').count();
                    if !self
                        .fields
                        .iter()
                        .map(|field| field.pointer)
                        .chain(self.native.iter().map(|field| field.pointer))
                        .chain(self.verified.iter().map(|field| field.pointer))
                        .any(|pointer_pattern| {
                            let segments = pointer_pattern.split('/').collect::<Vec<_>>();
                            segments.len() > parent_segments
                                && pointer_matches(
                                    &segments[..parent_segments].join("/"),
                                    pointer,
                                    self.source_root,
                                )
                        })
                    {
                        let counts = |values: &[Value]| {
                            let mut counts = BTreeMap::new();
                            for value in values {
                                *counts.entry(value.to_string()).or_insert(0usize) += 1;
                            }
                            counts
                        };
                        return if counts(source) == counts(target) {
                            Ok(())
                        } else {
                            Err(difference(pointer, "unordered multiset changed"))
                        };
                    }
                    if source.len() > 128 {
                        return Err(difference(
                            pointer,
                            "unordered collection exceeds 128 elements",
                        ));
                    }
                    return self.pair(
                        &MultisetSlice {
                            source,
                            target,
                            source_pointer: pointer,
                            target_pointer,
                            depth: depth + 1,
                        },
                        0,
                        &mut vec![false; target.len()],
                        decisions,
                    );
                }
                FieldContract::Time {
                    format,
                    relation,
                    anchor,
                    utc_offset,
                    clock_group,
                    clock_scope,
                } => {
                    let config = crate::policy::TimeContract {
                        format: *format,
                        relation: *relation,
                        anchor: *anchor,
                        utc_offset: utc_offset.clone(),
                        clock_group: clock_group.clone(),
                        clock_scope: clock_scope.clone(),
                    };
                    let result = compare_time(source, target, &config, self.clocks.get(*anchor));
                    let pair = result.map_err(|e| difference(pointer, &e.to_string()))?;
                    *decisions
                        .time_validations
                        .entry(field.rule_id.into())
                        .or_default() += 1;
                    // Civil dates already preserve the exact local-day relation.
                    // They do not share a nanosecond shift with instant fields.
                    if *format != TimestampFormat::CalendarDate {
                        let scope =
                            clock_scope::resolve(self, field, pointer, target_pointer, decisions)?;
                        let key = (*anchor, clock_group.clone(), scope);
                        if !decisions
                            .times
                            .get(&key)
                            .is_some_and(|times| times.contains(&pair))
                            && time_observation_count(&decisions.times, &key)
                                >= MAX_TIME_OBSERVATIONS
                        {
                            return Err(difference(
                                pointer,
                                "time relationship exceeds 4096 distinct observations",
                            ));
                        }
                        let relationships = decisions.times.entry(key).or_default();
                        if !relationships.contains(&pair) {
                            relationships.push(pair);
                        }
                    }
                    return validate_relationships(decisions)
                        .map_err(|e| difference(pointer, &e.to_string()));
                }
                FieldContract::Duration { unit, anchor } => {
                    use crate::policy::DurationUnit as U;
                    let unit = match unit {
                        U::Seconds => time::DurationUnit::Seconds,
                        U::Milliseconds => time::DurationUnit::Milliseconds,
                        U::Microseconds => time::DurationUnit::Microseconds,
                        U::Minutes => time::DurationUnit::Minutes,
                        U::Hours => time::DurationUnit::Hours,
                    };
                    let result = (|| {
                        time::validate_numeric_category(source, target)?;
                        let source = time::parse_duration(source, unit)?;
                        let target = time::parse_duration(target, unit)?;
                        time::compare_duration_nanos(source, target, self.clocks.get(*anchor))
                    })();
                    return result.map_err(|e| difference(pointer, &e.to_string()));
                }
            }
        }
        match (source, target) {
            (Value::Object(source), Value::Object(target)) => {
                if let Some(key) = source.keys().find(|key| !target.contains_key(*key)) {
                    return Err(difference(
                        &format!("{pointer}/{}", escape(key)),
                        "field presence changed",
                    ));
                }
                if let Some(key) = target.keys().find(|key| !source.contains_key(*key)) {
                    return Err(difference(
                        &format!("{pointer}/{}", escape(key)),
                        "unexpected field",
                    ));
                }
                for (key, source) in source {
                    let child = format!("{pointer}/{}", escape(key));
                    let target = target
                        .get(key)
                        .ok_or_else(|| difference(&child, "field presence changed"))?;
                    self.node(
                        source,
                        target,
                        &child,
                        &format!("{target_pointer}/{}", escape(key)),
                        decisions,
                        depth + 1,
                    )?;
                }
            }
            (Value::Array(source), Value::Array(target)) => {
                if source.len() != target.len() {
                    return Err(difference(pointer, "array cardinality changed"));
                }
                for (index, (source, target)) in source.iter().zip(target).enumerate() {
                    self.node(
                        source,
                        target,
                        &format!("{pointer}/{index}"),
                        &format!("{target_pointer}/{index}"),
                        decisions,
                        depth + 1,
                    )?;
                }
            }
            _ if source == target && same_type(source, target) => (),
            _ => return Err(difference(pointer, "unselected value or type changed")),
        }
        Ok(())
    }

    fn pair(
        &mut self,
        values: &MultisetSlice<'_>,
        index: usize,
        used: &mut [bool],
        decisions: &mut Decisions,
    ) -> Result<(), Difference> {
        if index == values.source.len() {
            return Ok(());
        }
        // Matching whole elements preserves associations between their fields.
        // Each speculative branch owns a copy of its decisions; failed branches
        // neither capture bindings nor leak time relationships to another match.
        for candidate in 0..values.target.len() {
            if used[candidate] {
                continue;
            }
            let mut staged = decisions.clone();
            if self
                .node(
                    &values.source[index],
                    &values.target[candidate],
                    &format!("{}/{index}", values.source_pointer),
                    &format!("{}/{candidate}", values.target_pointer),
                    &mut staged,
                    values.depth,
                )
                .is_err()
            {
                continue;
            }
            used[candidate] = true;
            if self.pair(values, index + 1, used, &mut staged).is_ok() {
                *decisions = staged;
                return Ok(());
            }
            used[candidate] = false;
            if self.remaining == 0 {
                break;
            }
        }
        Err(difference(
            values.source_pointer,
            "no bounded multiset pairing preserves all contracts",
        ))
    }
}

fn same_type(source: &Value, target: &Value) -> bool {
    std::mem::discriminant(source) == std::mem::discriminant(target)
        && (!source.is_number() || time::validate_numeric_category(source, target).is_ok())
}

pub(crate) fn core_format(format: TimestampFormat) -> Result<time::TimestampFormat, TimeError> {
    Ok(match format {
        TimestampFormat::UnixSeconds => time::TimestampFormat::UnixSeconds,
        TimestampFormat::UnixMilliseconds => time::TimestampFormat::UnixMilliseconds,
        TimestampFormat::UnixMicroseconds => time::TimestampFormat::UnixMicroseconds,
        TimestampFormat::Rfc3339 => time::TimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => time::TimestampFormat::AmzDate,
        TimestampFormat::Iso8601Naive => time::TimestampFormat::Iso8601Naive,
        TimestampFormat::SqlDatetime => time::TimestampFormat::SqlDatetime,
        TimestampFormat::CalendarDate => return Err(TimeError::InvalidValue),
    })
}

fn compare_time(
    source: &Value,
    target: &Value,
    config: &crate::policy::TimeContract,
    clocks: ClockPair,
) -> Result<(i128, i128), TimeError> {
    if !same_type(source, target) {
        return Err(TimeError::NumericCategoryChanged);
    }
    if matches!(
        config.format,
        TimestampFormat::UnixSeconds
            | TimestampFormat::UnixMilliseconds
            | TimestampFormat::UnixMicroseconds
    ) && !source.is_number()
    {
        return Err(TimeError::InvalidValue);
    }
    let offset = config.offset().map_err(|_| TimeError::InvalidValue)?;
    let mode = match config.relation {
        TimeRelation::RequestWindow => time::TimeMode::RequestWindow,
        TimeRelation::PreserveOffset => time::TimeMode::PreserveRelative,
    };
    if config.format == TimestampFormat::CalendarDate {
        return time::calendar::compare(
            source,
            target,
            offset.ok_or(TimeError::InvalidValue)?,
            mode,
            clocks,
        );
    }
    let source = time::parse_timestamp(source, core_format(config.format)?, offset)?;
    let target = time::parse_timestamp(target, core_format(config.format)?, offset)?;
    time::compare_timestamp_nanos(source, target, mode, clocks)?;
    Ok((source, target))
}

#[cfg(test)]
mod tests;
