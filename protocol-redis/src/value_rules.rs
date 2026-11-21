//! Native request positions and protected arguments delegate value semantics to the host.
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use traffic_contract::compare::Comparison;
use traffic_contract::identity::IdentityPair;
use traffic_contract::time::ClockPair;

use crate::values::{RedisContainer, RedisFieldValue, redis_field_values};

pub struct RequestComparison<I> {
    pub comparison: Comparison,
    pub identity: I,
}

/// Whole-message values also include publication payloads, which have no storage identity.
pub fn message_value_index(command: &str, length: usize) -> Option<usize> {
    match (command, length) {
        ("SET", 2..) | ("PUBLISH", 2) => Some(1),
        ("SETEX" | "PSETEX", 3) => Some(2),
        _ => None,
    }
}

pub fn request_values<'a>(command: &str, args: &'a [Vec<u8>]) -> Result<Vec<RedisFieldValue<'a>>> {
    let mut values = redis_field_values(command, args, None)?;
    if let Some(index) = message_value_index(command, args.len())
        && !values.iter().any(|value| value.argument == Some(index))
        && let (Some(key), Some(payload)) = (args.first(), args.get(index))
    {
        values.push(RedisFieldValue {
            container: RedisContainer::String,
            key,
            hash_field: None,
            payload: Some(payload),
            stored: false,
            argument: Some(index),
            response: None,
        });
    }
    Ok(values)
}

/// Value comparison and the identity decision belong to the supplied services.
/// The returned identity remains opaque until the caller's delivery transaction.
pub fn compare_request<I>(
    command: &str,
    source: &[Vec<u8>],
    actual: &[Vec<u8>],
    clocks: ClockPair,
    tolerance: Duration,
    mut compare_value: impl FnMut(&RedisFieldValue<'_>, &[u8], &[u8]) -> Result<Comparison>,
    project_references: impl FnOnce(&Comparison, &[Vec<u8>]) -> Result<(I, Option<Vec<Vec<u8>>>)>,
) -> Result<Option<RequestComparison<I>>> {
    let values = request_values(command, source)?;
    if values.is_empty() {
        return Ok(None);
    }
    ensure!(source.len() == actual.len(), "Redis argument count changed");
    let normalized = crate::expiration::normalize(command, source, actual, tolerance, |scale| {
        let (source, target) = clocks.require()?;
        Ok(if scale == 1000 {
            (source.timestamp_millis(), target.timestamp_millis())
        } else {
            (source.timestamp(), target.timestamp())
        })
    })?;
    let actual = normalized.as_deref().unwrap_or(actual);
    let indices = values
        .iter()
        .filter_map(|value| value.argument)
        .collect::<BTreeSet<_>>();
    let mut merged = Comparison::default();
    for value in &values {
        let index = value
            .argument
            .context("Redis write has no argument position")?;
        let mut comparison = compare_value(value, &source[index], &actual[index])?;
        ensure!(
            comparison.passed(),
            "Redis global value contract failed: {:?}",
            comparison.differences
        );
        comparison.scope_schema_clocks(index);
        merged.merge_and_validate(comparison);
    }
    ensure!(
        merged.passed(),
        "Redis value relationships changed: {:?}",
        merged.differences
    );
    let (identity, keys) = project_references(&merged, actual)?;
    let actual = keys.as_deref().unwrap_or(actual);
    ensure!(
        source.len() == actual.len(),
        "Redis reference projection changed argument count"
    );
    ensure!(
        source
            .iter()
            .zip(actual)
            .enumerate()
            .all(|(index, (a, b))| indices.contains(&index) || a == b),
        "Redis key, hash field, index or unselected options/arguments changed"
    );
    Ok(Some(RequestComparison {
        comparison: merged,
        identity,
    }))
}

/// Native key slots and opaque script arguments can consume an accepted reference.
/// Content recognition and correspondence lookup are provided by the host.
pub fn project_key_references(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    pairs: &[IdentityPair],
    is_structured: impl Fn(&[u8]) -> bool,
    mut knows_identity: impl FnMut(&str, &str) -> Result<bool>,
) -> Result<Option<Vec<Vec<u8>>>> {
    ensure!(source.len() == target.len(), "Redis argument count changed");
    let mut projected = None;
    let mut positions = crate::key_slots::key_indices(command, source)?;
    if matches!(command, "EVAL" | "EVALSHA") {
        let start = 2 + std::str::from_utf8(&source[1])?.parse::<usize>()?;
        positions.extend((start..source.len()).filter(|&index| !is_structured(&source[index])));
    } else if command == "DELEX" && source.len() == 3 && source[1].eq_ignore_ascii_case(b"IFEQ") {
        positions.push(2);
    }
    for index in positions {
        if source[index] == target[index] {
            continue;
        }
        let (Ok(a), Ok(b)) = (
            std::str::from_utf8(&source[index]),
            std::str::from_utf8(&target[index]),
        ) else {
            continue;
        };
        let source_key = serde_json::to_string(a)?;
        let target_key = serde_json::to_string(b)?;
        if pairs
            .iter()
            .any(|pair| pair.source == source_key && pair.target == target_key)
            || knows_identity(a, b)?
        {
            projected.get_or_insert_with(|| target.to_vec())[index] = source[index].clone();
        }
    }
    Ok(projected)
}

#[cfg(test)]
mod tests;
