//! Resource-field evidence shares live Replay's logical Redis carriers.
use super::*;
use crate::policy::Slot;
use crate::replay::{RedisFieldValue, redis_field_values, redis_response_identities};
use crate::value_codec::CodecPlan;
use crate::value_contract::{encoded, json::Comparison, time::ClockPair};
use std::{borrow::Cow, sync::Arc};

#[cfg(test)]
mod tests;

type Plans<'a> = BTreeMap<Vec<&'a str>, Arc<CodecPlan>>;

fn matches(
    rule: &CompiledRule,
    value: &RedisFieldValue<'_>,
    command: &str,
    surface: Surface,
) -> bool {
    if rule.rule.surface != surface
        || rule
            .rule
            .selector
            .operation
            .as_deref()
            .is_some_and(|operation| operation != command)
    {
        return false;
    }
    let slot = match rule.rule.slot {
        Slot::RedisValue(container) => container == value.container,
        Slot::Value if surface == Surface::DependencyRequest => {
            let index = match command {
                "SET" => Some(1),
                "SETEX" | "PSETEX" => Some(2),
                _ => None,
            };
            value.argument == index && index.is_some()
        }
        Slot::Value => matches!(command, "GET" | "HGET"),
        _ => false,
    };
    slot && rule
        .rule
        .selector
        .key
        .as_ref()
        .is_some_and(|key| key.matches(value.key))
        && rule.rule.selector.hash_field.as_ref().is_none_or(|field| {
            value.hash_field.is_some_and(|value| field.matches(value))
                || (command == "HGETALL" && value.hash_field.is_none())
        })
}

pub(super) fn selects(rule: &CompiledRule, event: &Value) -> Result<bool> {
    Ok(!select_rules(&[rule], event)?.is_empty())
}

/// The caller has already checked resource identity and case scope. Resolve the
/// command once even when many declared fields select its logical values.
pub(super) fn select_rules<'a>(
    rules: &[&'a CompiledRule],
    event: &Value,
) -> Result<Vec<&'a CompiledRule>> {
    let Some(first) = rules.first() else {
        return Ok(Vec::new());
    };
    let surface = first.rule.surface;
    ensure!(
        rules.iter().all(|rule| rule.rule.surface == surface),
        "mixed Redis selection surfaces"
    );
    let args = arguments(event)?;
    let command = event["command"]
        .as_str()
        .context("Redis command unavailable")?;
    if surface == Surface::DependencyResponse {
        let identities = redis_response_identities(command, &args)?;
        if !identities.iter().any(|value| {
            rules
                .iter()
                .any(|rule| matches(rule, value, command, surface))
        }) {
            return Ok(Vec::new());
        }
    }
    let raw = if surface == Surface::DependencyResponse {
        Some(capture(&event["response"])?)
    } else {
        None
    };
    let values = redis_field_values(command, &args, raw.as_deref())?;
    Ok(rules
        .iter()
        .copied()
        .filter(|rule| {
            values
                .iter()
                .any(|value| matches(rule, value, command, surface))
        })
        .collect())
}

fn selected<'a>(
    rules: &[&'a CompiledRule],
    value: &RedisFieldValue<'_>,
    command: &str,
    surface: Surface,
) -> Vec<&'a CompiledRule> {
    rules
        .iter()
        .copied()
        .filter(|rule| matches(rule, value, command, surface))
        .collect()
}

fn plan<'a>(rules: &[&'a CompiledRule], plans: &mut Plans<'a>) -> Result<Arc<CodecPlan>> {
    let key = rules
        .iter()
        .map(|rule| rule.rule.id.as_str())
        .collect::<Vec<_>>();
    if let Some(plan) = plans.get(&key) {
        return Ok(Arc::clone(plan));
    }
    let plan = encoded::prepared_codec(rules)?;
    plans.insert(key, Arc::clone(&plan));
    Ok(plan)
}

fn source_clocks(clocks: AnchorClocks) -> AnchorClocks {
    let original = |pair: ClockPair| ClockPair {
        source: pair.source,
        target: pair.source,
    };
    AnchorClocks {
        case: original(clocks.case),
        dependency: original(clocks.dependency),
        delivery: original(clocks.delivery),
    }
}

pub(super) fn source(
    surface: Surface,
    event: &Value,
    raw: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    let args = if surface == Surface::DependencyRequest {
        serde_json::from_slice(raw)?
    } else {
        arguments(event)?
    };
    let command = event["command"]
        .as_str()
        .context("Redis command unavailable")?;
    let values = redis_field_values(
        command,
        &args,
        (surface == Surface::DependencyResponse).then_some(raw),
    )?;
    let mut comparison = Comparison::default();
    let mut plans = Plans::new();
    for value in &values {
        let group = selected(rules, value, command, surface);
        if group.is_empty() {
            continue;
        }
        let Some(payload) = value.payload else {
            continue;
        };
        let decoded = plan(&group, &mut plans)?.decode(payload)?;
        for pointer in group.iter().flat_map(|rule| rule.delivery_time.keys()) {
            ensure!(
                crate::value_contract::json::pointer_observed(&decoded.logical, pointer),
                "delivery timestamp {pointer:?} was not observed"
            );
        }
        let mut checked =
            encoded::compare_decoded(&decoded, &decoded, &group, source_clocks(clocks))?;
        checked.scope_schema_clocks(
            value
                .argument
                .or_else(|| value.response.as_ref().map(|range| range.start))
                .unwrap_or_default(),
        );
        comparison.merge_and_validate(checked);
    }
    ensure!(
        comparison.passed(),
        "Source Redis field contract failed: {:?}",
        comparison.differences
    );
    Ok(comparison.evaluated)
}

pub(super) fn pair(
    surface: Surface,
    event: &Value,
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<usize> {
    pair_with_time_copies(surface, event, source, target, rules, clocks, None)
}

pub(super) fn pair_with_time_copies(
    surface: Surface,
    event: &Value,
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: Option<(&crate::value_contract::time_copies::TimeCopyStore, &str)>,
) -> Result<usize> {
    let command = event["command"]
        .as_str()
        .context("Redis command unavailable")?;
    if surface == Surface::DependencyRequest {
        return request_pair(event, command, source, target, rules, clocks, copies);
    }
    let args = arguments(event)?;
    let values = redis_field_values(command, &args, Some(source))?;
    let mut output = Vec::with_capacity(source.len());
    let mut previous = 0;
    let mut comparison = Comparison::default();
    let mut plans = Plans::new();
    for value in &values {
        let group = selected(rules, value, command, surface);
        if group.is_empty() {
            continue;
        }
        let (Some(payload), Some(range)) = (value.payload, value.response.as_ref()) else {
            continue;
        };
        ensure!(
            range.start >= previous,
            "overlapping Redis evidence value slots"
        );
        let decoded = plan(&group, &mut plans)?.decode(payload)?;
        let mut checked =
            encoded::compare_decoded(&decoded, &decoded, &group, source_clocks(clocks))?;
        checked.scope_schema_clocks(range.start);
        comparison.merge_and_validate(checked);
        let delivered = if group.iter().all(|rule| rule.delivery_time.is_empty()) {
            Cow::Borrowed(payload)
        } else {
            Cow::Owned(encoded::materialize_decoded(&decoded, &group, clocks)?)
        };
        output.extend_from_slice(&source[previous..range.start]);
        let header_len = range.len() - payload.len() - 2;
        if delivered.len() == payload.len() {
            output.extend_from_slice(&source[range.start..range.start + header_len]);
        } else {
            output.extend_from_slice(format!("${}\r\n", delivered.len()).as_bytes());
        }
        output.extend_from_slice(&delivered);
        output.extend_from_slice(b"\r\n");
        previous = range.end;
    }
    ensure!(
        comparison.passed(),
        "Source Redis response field contract failed: {:?}",
        comparison.differences
    );
    output.extend_from_slice(&source[previous..]);
    ensure!(
        output == target,
        "Redis derived response changed an unselected value or protocol frame"
    );
    Ok(comparison.evaluated.len())
}

#[allow(clippy::too_many_arguments)] // Wire envelopes, observed storage scope, and optional proven inputs form one candidate.
fn request_pair(
    event: &Value,
    command: &str,
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
    copies: Option<(&crate::value_contract::time_copies::TimeCopyStore, &str)>,
) -> Result<usize> {
    let surface = Surface::DependencyRequest;
    let expected: Vec<Vec<u8>> = serde_json::from_slice(source)?;
    let actual: Vec<Vec<u8>> = serde_json::from_slice(target)?;
    let source_values = redis_field_values(command, &expected, None)?;
    let target_values = redis_field_values(command, &actual, None)?;
    // Search candidates outside every selected key supply no Target proof.
    if !target_values
        .iter()
        .any(|value| !selected(rules, value, command, surface).is_empty())
    {
        return Ok(0);
    }
    ensure!(
        expected.len() == actual.len(),
        "Redis argument inventory changed"
    );
    ensure!(
        source_values.len() == target_values.len(),
        "Redis field inventory changed"
    );
    let mut allowed = BTreeSet::new();
    let mut comparison = Comparison::default();
    let mut plans = Plans::new();
    for (before, after) in source_values.iter().zip(&target_values) {
        ensure!(
            before.key == after.key
                && before.hash_field == after.hash_field
                && before.container == after.container
                && before.argument == after.argument,
            "Redis storage identity changed"
        );
        let group = selected(rules, before, command, surface);
        if group.is_empty() {
            continue;
        }
        let index = before.argument.context("Redis write argument missing")?;
        allowed.insert(index);
        let plan = plan(&group, &mut plans)?;
        let expected = plan.decode(&expected[index])?;
        let actual = plan.decode(&actual[index])?;
        let mut proofs = Vec::new();
        if let Some((store, case)) = copies {
            let host = event["target_host"]
                .as_str()
                .context("Redis copy lacks observed endpoint")?;
            let port = u16::try_from(
                event["target_port"]
                    .as_u64()
                    .context("Redis copy lacks observed port")?,
            )?;
            let database = event["database"]
                .as_i64()
                .context("Redis copy lacks observed database")?;
            proofs = crate::replay::redis_time_write_proofs(
                store,
                case,
                crate::replay::redis_time_position(host, port, database, before),
                crate::replay::redis_time_position(host, port, database, after),
                &expected,
                &group,
            )?;
        }
        let mut checked =
            encoded::compare_decoded_with_time_copies(&expected, &actual, &group, clocks, &proofs)?;
        checked.scope_schema_clocks(index);
        comparison.merge_and_validate(checked);
    }
    for (index, (before, after)) in expected.iter().zip(&actual).enumerate() {
        ensure!(
            allowed.contains(&index) || before == after,
            "unselected Redis key/options/argument changed at {index}"
        );
    }
    ensure!(
        comparison.passed(),
        "Redis field contract failed: {:?}",
        comparison.differences
    );
    Ok(comparison.evaluated.len())
}
