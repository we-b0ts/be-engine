//! A complete Source trace exercises domain contracts in isolated policy state.
//! Equal Source copies are self validation, never Independent Target evidence.
mod coverage;
mod http;
mod input;
mod mysql;
mod redis;
mod signed_input;
#[cfg(test)]
mod tests;
use super::*;
use crate::policy::{CompiledPolicy, NativeEffect};
use crate::replay::policy::matcher::ReplayPolicyRuntime;
use anyhow::ensure;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(crate) struct NativeSourceCase<'a> {
    pub id: &'a str,
    pub dir: &'a Path,
    pub request: &'a Value,
    pub events: &'a [Value],
}
#[derive(Default)]
pub(crate) struct NativeSourceDependencyValidation {
    pub rules: BTreeMap<String, usize>,
    pub key_witnesses: BTreeSet<(PathBuf, String)>,
}

pub(crate) fn validate_native_source_dependencies(
    compiled: &CompiledPolicy,
    selected_rule_ids: &BTreeSet<String>,
    target_root: &Path,
    cases: &[NativeSourceCase<'_>],
) -> Result<NativeSourceDependencyValidation> {
    let mut requests = BTreeMap::new();
    for case in cases {
        ensure!(
            requests
                .insert(
                    case.id.to_owned(),
                    (case.dir.to_owned(), case.request.clone())
                )
                .is_none(),
            "duplicate Source Case identity"
        );
    }
    let mut runtime = ReplayPolicyRuntime::from_source_policy(compiled, target_root, &requests)?;
    let mut redis_state = crate::replay::redis::RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let mut checked = NativeSourceDependencyValidation::default();
    let mut coverage = coverage::Coverage::default();
    let mut identities = BTreeSet::new();
    for case in cases {
        input::validate(compiled, target_root, case, &mut checked)?;
        signed_input::validate(compiled, target_root, case, &mut checked)?;
        redis::register_callbacks(&mut redis_state, case)?;
        for event in ordered(case.events)? {
            if event["session_setup"] != true
                && let (Some(connection), Some(sequence)) = (
                    event["connection_id"].as_str(),
                    event["sequence"]
                        .as_u64()
                        .or_else(|| event["query_sequence"].as_u64()),
                )
            {
                ensure!(
                    identities.insert((connection.to_owned(), sequence)),
                    "duplicate complete Source exchange identity"
                );
            }
            let validation = match event["event_type"].as_str() {
                Some("redis_exchange") => redis::validate(
                    &mut runtime,
                    &mut redis_state,
                    &mut targets,
                    case,
                    event,
                    &mut coverage,
                ),
                Some("http_exchange") => http::validate(&mut runtime, case, event, &mut coverage),
                Some("mysql_exchange") => mysql::validate(&mut runtime, case, event, &mut coverage),
                _ => Ok(()),
            };
            validation.with_context(|| format!(
                "Source dependency proof failed: case={}, event_type={}, connection_id={}, sequence={}",
                case.id,
                event["event_type"].as_str().unwrap_or("unknown"),
                event["connection_id"].as_str().unwrap_or("unknown"),
                event["sequence"].as_u64().or_else(|| event["query_sequence"].as_u64())
                    .map_or_else(|| "unknown".into(), |sequence| sequence.to_string()),
            ))?;
        }
    }
    runtime.request_contracts.finish_source_session()?;
    // A value-only read-back needs a real Source write/read proof even when
    // observation-count ownership belongs to a separate state contract.
    for proof in runtime.request_contracts.read_back_report() {
        *checked.rules.entry(proof.rule_id).or_default() += 1;
    }
    for row in runtime.report().dependency_rules {
        if row.matches > 0 {
            *checked.rules.entry(row.id).or_default() += row.matches;
        }
    }
    for (id, count) in
        crate::replay::redis::append::validate_source(&runtime.request_contracts, cases)?
    {
        *checked.rules.entry(id).or_default() += count;
    }
    for (id, count) in
        crate::replay::redis::read_commutation::validate_source(&runtime.request_contracts, cases)?
    {
        *checked.rules.entry(id).or_default() += count;
    }
    for (id, count) in
        crate::replay::redis::observations::validate_source(&runtime.request_contracts, cases)?
    {
        *checked.rules.entry(id).or_default() += count;
    }
    for key in runtime.request_contracts.signing_keys() {
        checked.key_witnesses.extend(key.witnesses().cloned());
    }
    for (id, count) in
        crate::replay::redis::activity::validate_source(&runtime.request_contracts, cases)?
    {
        *checked.rules.entry(id).or_default() += count;
    }
    checked.rules.retain(|id, _| {
        compiled
            .native
            .iter()
            .any(|rule| rule.rule.id == *id && dependency_effect(&rule.rule.effect))
    });
    coverage.finish(compiled, selected_rule_ids, &checked.rules)?;
    runtime
        .request_contracts
        .validate_read_back_coverage(selected_rule_ids)?;
    Ok(checked)
}

fn dependency_effect(effect: &NativeEffect) -> bool {
    matches!(
        effect,
        NativeEffect::Identity(_)
            | NativeEffect::RedisAppendStream
            | NativeEffect::RedisReadCommutation(_)
            | NativeEffect::RedisReadObservation(_)
            | NativeEffect::RedisExpiryRefresh(_)
            | NativeEffect::RedisActivityRefresh(_)
            | NativeEffect::RedisSequence(_)
            | NativeEffect::HttpRequest(_)
            | NativeEffect::MysqlValues(_)
            | NativeEffect::InputJwt(_)
            | NativeEffect::InputSignedTimestamp(_)
    )
}

fn started(event: &Value) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    if let Some(value) = event["request_started_at"].as_str() {
        return Ok(Some(value.parse()?));
    }
    let Some(value) = event["timestamp"].as_str() else {
        return Ok(None);
    };
    let completed = value.parse::<chrono::DateTime<chrono::Utc>>()?;
    let duration = event["duration_ms"]
        .as_u64()
        .context("Source duration is missing or invalid")?;
    Ok(Some(
        completed
            .checked_sub_signed(chrono::TimeDelta::milliseconds(i64::try_from(duration)?))
            .context("Source request clock overflow")?,
    ))
}

/// JSONL is completion ordered. Use explicit original request clocks where
/// available, and verify they do not reverse a recorded connection sequence.
fn ordered(events: &[Value]) -> Result<Vec<&Value>> {
    let mut events = events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(
                event["event_type"].as_str(),
                Some("redis_exchange" | "http_exchange" | "mysql_exchange")
            )
        })
        .map(|(index, event)| Ok((started(event)?, index, event)))
        .collect::<Result<Vec<_>>>()?;
    events.sort_by_key(|(clock, index, _)| (*clock, *index));
    let mut lanes = BTreeMap::new();
    for (_, _, event) in &events {
        if event["session_setup"] == true {
            continue;
        }
        if let (Some(connection), Some(sequence)) = (
            event["connection_id"].as_str(),
            event["sequence"]
                .as_u64()
                .or_else(|| event["query_sequence"].as_u64()),
        ) && let Some(previous) = lanes.insert(connection, sequence)
        {
            ensure!(
                previous < sequence,
                "Source clocks reverse or repeat a connection lane"
            );
        }
    }
    Ok(events.into_iter().map(|(_, _, event)| event).collect())
}
