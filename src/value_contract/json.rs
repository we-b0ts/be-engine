//! Pure, bounded comparison of a decoded value. Protocol admission and commits
//! remain with the caller. Selected fields compose before the strict remainder.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use super::time::{self, ClockPair, TimeError};
use crate::policy::{FieldContract, TimeAnchor, TimeRelation, TimestampFormat};

const MAX_COMPARISONS: usize = 16_384;
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AnchorClocks {
    pub(crate) case: ClockPair,
    pub(crate) dependency: ClockPair,
    pub(crate) delivery: ClockPair,
}

impl AnchorClocks {
    fn get(self, anchor: TimeAnchor) -> ClockPair {
        match anchor {
            TimeAnchor::ApiRequestStart => self.case,
            TimeAnchor::DependencyRequestStart => self.dependency,
            TimeAnchor::DependencyDelivery => self.delivery,
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
    pub(crate) relationships: BTreeMap<(TimeAnchor, Option<String>), Vec<(i128, i128)>>,
}

impl Comparison {
    pub(crate) fn passed(&self) -> bool {
        self.differences.is_empty()
    }
    pub(crate) fn merge_and_validate(&mut self, other: Comparison) {
        self.evaluated.extend(other.evaluated);
        self.differences.extend(other.differences);
        for (rule_id, count) in other.time_validations {
            *self.time_validations.entry(rule_id).or_default() += count;
        }
        for (scope, values) in other.relationships {
            self.relationships.entry(scope).or_default().extend(values);
        }
        if let Some(error) = self
            .relationships
            .values()
            .find_map(|values| time::validate_relationships(values).err())
        {
            self.differences.push(difference("", &error.to_string()));
        }
    }
}

#[derive(Clone, Default)]
struct Decisions {
    evaluated: BTreeSet<String>,
    selected: BTreeSet<usize>,
    times: BTreeMap<(TimeAnchor, Option<String>), Vec<(i128, i128)>>,
    time_validations: BTreeMap<String, usize>,
}

struct Comparator<'a> {
    fields: &'a [Field<'a>],
    clocks: AnchorClocks,
    remaining: usize,
    source_root: &'a Value,
}

pub(crate) fn compare(
    source: &Value,
    target: &Value,
    fields: &[Field<'_>],
    clocks: AnchorClocks,
) -> Comparison {
    let mut comparator = Comparator {
        fields,
        clocks,
        remaining: MAX_COMPARISONS,
        source_root: source,
    };
    let mut decisions = Decisions::default();
    let result = comparator
        .node(source, target, "", &mut decisions, 0)
        .and_then(|()| {
            if decisions.selected.len() != fields.len() {
                let missing = fields
                    .iter()
                    .enumerate()
                    .find(|(i, _)| !decisions.selected.contains(i))
                    .unwrap()
                    .1;
                return Err(difference(
                    missing.pointer,
                    "selected field was not observed",
                ));
            }
            validate_relationships(&decisions).map_err(|e| difference("", &e.to_string()))
        });
    Comparison {
        evaluated: decisions.evaluated,
        time_validations: decisions.time_validations,
        differences: result.err().into_iter().collect(),
        relationships: decisions.times,
    }
}

fn difference(pointer: &str, reason: &str) -> Difference {
    Difference {
        pointer: pointer.into(),
        reason: reason.into(),
    }
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
        if selected.len() > 1 {
            return Err(difference(pointer, "conflicting field contracts"));
        }
        if let Some((index, field)) = selected.first() {
            decisions.selected.insert(*index);
            decisions.evaluated.insert(field.rule_id.into());
            match field.contract {
                FieldContract::Unordered => {
                    let (Some(source), Some(target)) = (source.as_array(), target.as_array())
                    else {
                        return Err(difference(pointer, "unordered requires two arrays"));
                    };
                    if source.len() != target.len() {
                        return Err(difference(pointer, "array cardinality changed"));
                    }
                    let parent_segments = pointer.split('/').count();
                    if !self.fields.iter().any(|field| {
                        let segments = field.pointer.split('/').collect::<Vec<_>>();
                        segments.len() > parent_segments
                            && pointer_matches(
                                &segments[..parent_segments].join("/"),
                                pointer,
                                self.source_root,
                            )
                    }) {
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
                        source,
                        target,
                        pointer,
                        0,
                        &mut vec![false; target.len()],
                        decisions,
                        depth + 1,
                    );
                }
                FieldContract::Time {
                    format,
                    relation,
                    anchor,
                    utc_offset,
                    clock_group,
                } => {
                    let config = crate::policy::TimeContract {
                        format: *format,
                        relation: *relation,
                        anchor: *anchor,
                        utc_offset: utc_offset.clone(),
                        clock_group: clock_group.clone(),
                    };
                    let result = compare_time(source, target, &config, self.clocks.get(*anchor));
                    let pair = result.map_err(|e| difference(pointer, &e.to_string()))?;
                    *decisions
                        .time_validations
                        .entry(field.rule_id.into())
                        .or_default() += 1;
                    decisions
                        .times
                        .entry((*anchor, clock_group.clone()))
                        .or_default()
                        .push(pair);
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
                if source.len() != target.len() {
                    return Err(difference(pointer, "object cardinality changed"));
                }
                for (key, source) in source {
                    let child = format!("{pointer}/{}", escape(key));
                    let target = target
                        .get(key)
                        .ok_or_else(|| difference(&child, "field presence changed"))?;
                    self.node(source, target, &child, decisions, depth + 1)?;
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
        source: &[Value],
        target: &[Value],
        pointer: &str,
        index: usize,
        used: &mut [bool],
        decisions: &mut Decisions,
        depth: usize,
    ) -> Result<(), Difference> {
        if index == source.len() {
            return Ok(());
        }
        // Matching whole elements preserves associations between their fields.
        // Each speculative branch owns a copy of its decisions; failed branches
        // neither capture bindings nor leak time relationships to another match.
        for candidate in 0..target.len() {
            if used[candidate] {
                continue;
            }
            let mut staged = decisions.clone();
            if self
                .node(
                    &source[index],
                    &target[candidate],
                    &format!("{pointer}/{index}"),
                    &mut staged,
                    depth,
                )
                .is_err()
            {
                continue;
            }
            used[candidate] = true;
            if self
                .pair(source, target, pointer, index + 1, used, &mut staged, depth)
                .is_ok()
            {
                *decisions = staged;
                return Ok(());
            }
            used[candidate] = false;
            if self.remaining == 0 {
                break;
            }
        }
        Err(difference(
            pointer,
            "no bounded multiset pairing preserves all contracts",
        ))
    }
}

fn same_type(source: &Value, target: &Value) -> bool {
    std::mem::discriminant(source) == std::mem::discriminant(target)
        && (!source.is_number() || time::validate_numeric_category(source, target).is_ok())
}

pub(crate) fn core_format(format: TimestampFormat) -> time::TimestampFormat {
    match format {
        TimestampFormat::UnixSeconds => time::TimestampFormat::UnixSeconds,
        TimestampFormat::UnixMilliseconds => time::TimestampFormat::UnixMilliseconds,
        TimestampFormat::UnixMicroseconds => time::TimestampFormat::UnixMicroseconds,
        TimestampFormat::Rfc3339 => time::TimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => time::TimestampFormat::AmzDate,
        TimestampFormat::Iso8601Naive => time::TimestampFormat::Iso8601Naive,
    }
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
    let source = time::parse_timestamp(source, core_format(config.format), offset)?;
    let target = time::parse_timestamp(target, core_format(config.format), offset)?;
    let mode = match config.relation {
        TimeRelation::RequestWindow => time::TimeMode::RequestWindow,
        TimeRelation::PreserveOffset => time::TimeMode::PreserveRelative,
    };
    time::compare_timestamp_nanos(source, target, mode, clocks)?;
    Ok((source, target))
}

#[cfg(test)]
mod tests;
