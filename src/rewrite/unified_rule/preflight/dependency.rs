//! Protocol admission and immutable envelopes stay outside the encoded value core.
use crate::{
    policy::{CompiledNativeRule, CompiledRule, Database, Protocol, Surface},
    policy_evidence::WitnessRef,
    value_contract::{encoded, json::AnchorClocks},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[cfg(test)]
#[path = "mysql_fields_tests.rs"]
mod mysql_fields_tests;

pub(in crate::rewrite::unified_rule) fn protocol(event: &Value) -> Option<Protocol> {
    match event["event_type"].as_str()? {
        "redis_exchange" => Some(Protocol::Redis),
        "memcached_exchange" => Some(Protocol::Memcached),
        "http_exchange" => Some(Protocol::Http),
        "mysql_exchange" => Some(Protocol::Mysql),
        _ => None,
    }
}

fn resource_scope_matches(rule: &CompiledRule, event: &Value) -> Result<bool> {
    let resource = rule
        .rule
        .selector
        .resource
        .as_ref()
        .context("dependency rule lacks resource")?;
    if protocol(event) != Some(resource.protocol) {
        return Ok(false);
    }
    if resource.protocol == Protocol::Http {
        return Ok(true);
    }
    ensure!(
        matches!(
            resource.protocol,
            Protocol::Redis | Protocol::Memcached | Protocol::Mysql
        ),
        "selected protocol requires its installed native preflight adapter"
    );
    if !event["target_host"]
        .as_str()
        .is_some_and(|h| h.eq_ignore_ascii_case(&resource.endpoint.host))
        || event["target_port"].as_u64() != Some(u64::from(resource.endpoint.port))
        || resource.database.as_ref().is_some_and(|d| {
            !matches!(rule.rule.slot, crate::policy::Slot::SqlField(_))
                && !database_matches(d, &event["database"])
        })
        || resource
            .username
            .as_ref()
            .is_some_and(|u| event["username"].as_str() != Some(u))
        || rule
            .rule
            .selector
            .operation
            .as_ref()
            .is_some_and(|operation| {
                !event["command"]
                    .as_str()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(operation))
            })
    {
        return Ok(false);
    }
    Ok(true)
}

pub(in crate::rewrite::unified_rule) fn selects(
    rule: &CompiledRule,
    event: &Value,
) -> Result<bool> {
    if !resource_scope_matches(rule, event)? {
        return Ok(false);
    }
    let resource = rule
        .rule
        .selector
        .resource
        .as_ref()
        .expect("checked resource");
    if resource.protocol == Protocol::Http {
        return crate::replay::http_witness_matches(event, rule);
    }
    if resource.protocol == Protocol::Mysql {
        return crate::replay::mysql_witness_matches(event, rule);
    }
    if matches!(rule.rule.slot, crate::policy::Slot::RedisValue(_)) {
        return super::redis_fields::selects(rule, event);
    }
    if let Some(field) = &rule.rule.selector.hash_field
        && !super::arguments(event)?
            .get(1)
            .is_some_and(|value| field.matches(value))
    {
        return Ok(false);
    }
    Ok(keys(event)?.iter().any(|key| {
        rule.rule
            .selector
            .key
            .as_ref()
            .is_none_or(|s| s.matches(key))
    }))
}

/// Batch semantic Redis selection so one event is decoded once per surface.
pub(super) fn selected_rules<'a>(
    rules: &[&'a CompiledRule],
    event: &Value,
) -> Result<Vec<&'a CompiledRule>> {
    let mut result = Vec::new();
    let mut semantic = Vec::new();
    for rule in rules {
        if protocol(event) == Some(Protocol::Redis)
            && matches!(rule.rule.slot, crate::policy::Slot::RedisValue(_))
        {
            if resource_scope_matches(rule, event)? {
                semantic.push(*rule);
            }
        } else if selects(rule, event)? {
            result.push(*rule);
        }
    }
    result.extend(super::redis_fields::select_rules(&semantic, event)?);
    Ok(result)
}

pub(super) fn selects_native_sql(rule: &CompiledNativeRule, event: &Value) -> Result<bool> {
    let Some(resource) = &rule.rule.selector.resource else {
        return Ok(false);
    };
    if resource.protocol != Protocol::Mysql || protocol(event) != Some(Protocol::Mysql) {
        return Ok(false);
    }
    if !event["target_host"]
        .as_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&resource.endpoint.host))
        || event["target_port"].as_u64() != Some(u64::from(resource.endpoint.port))
        || resource
            .database
            .as_ref()
            .is_some_and(|database| !database_matches(database, &event["database"]))
        || resource
            .username
            .as_ref()
            .is_some_and(|username| event["username"].as_str() != Some(username))
        || rule
            .rule
            .selector
            .operation
            .as_ref()
            .is_some_and(|operation| {
                !event["command"]
                    .as_str()
                    .is_some_and(|command| command.eq_ignore_ascii_case(operation))
            })
    {
        return Ok(false);
    }
    crate::replay::mysql_native_witness_matches(event, rule)
}

fn keys(event: &Value) -> Result<Vec<Vec<u8>>> {
    if protocol(event) == Some(Protocol::Redis) {
        return Ok(super::arguments(event)?.into_iter().take(1).collect());
    }
    let mut keys = if event["key"].is_null() {
        Vec::new()
    } else {
        vec![super::capture(&event["key"])?]
    };
    if event["command"]
        .as_str()
        .is_some_and(|command| matches!(command.to_ascii_uppercase().as_str(), "GET" | "GETS"))
    {
        keys.extend(
            event["args"]
                .as_array()
                .into_iter()
                .flatten()
                .map(super::capture)
                .collect::<Result<Vec<_>>>()?,
        );
    }
    Ok(keys)
}

pub(in crate::rewrite::unified_rule) fn source_witness(
    surface: Surface,
    event: &Value,
    key_context: &Path,
) -> Result<Vec<u8>> {
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis if surface == Surface::DependencyRequest => {
            Ok(serde_json::to_vec(&super::arguments(event)?)?)
        }
        Protocol::Redis => super::capture(&event["response"]),
        Protocol::Memcached => crate::replay::memcached_source_witness(event, surface),
        Protocol::Mysql => crate::replay::mysql_source_witness(event, surface),
        Protocol::Http => crate::replay::http_source_witness(event, surface, key_context),
    }
}

pub(in crate::rewrite::unified_rule) fn validate_metadata(
    witness: &WitnessRef,
    event: &Value,
) -> Result<()> {
    if protocol(event) == Some(Protocol::Http) {
        return crate::replay::http_witness_metadata_matches(event, &witness.metadata);
    }
    let resource = witness
        .metadata
        .resource
        .as_ref()
        .context("witness has no protocol identity")?;
    ensure!(
        protocol(event) == Some(resource.protocol)
            && event["target_host"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&resource.endpoint.host))
            && event["target_port"].as_u64() == Some(u64::from(resource.endpoint.port))
            && resource
                .database
                .as_ref()
                .map(|d| database_matches(d, &event["database"]))
                .unwrap_or(event["database"].is_null())
            && resource.username.as_deref() == event["username"].as_str()
            && event["command"]
                .as_str()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&witness.metadata.operation)),
        "Target witness protocol identity differs from its immutable Source exchange"
    );
    Ok(())
}

pub(super) fn compare_source(
    surface: Surface,
    event: &Value,
    raw: &[u8],
    rules: &[&CompiledRule],
    native: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    if protocol(event) == Some(Protocol::Redis)
        && rules
            .iter()
            .any(|rule| matches!(rule.rule.slot, crate::policy::Slot::RedisValue(_)))
    {
        return super::redis_fields::source(surface, event, raw, rules, clocks);
    }
    if protocol(event) == Some(Protocol::Mysql) {
        let mut checked = BTreeSet::new();
        if surface == Surface::DependencyResponse && event["response"]["status"] != "resultset" {
            return Ok(checked);
        }
        let report = if surface == Surface::DependencyRequest {
            crate::replay::mysql_validate_contract_witness(
                event["database"].as_str(),
                raw,
                raw,
                rules,
                native,
                clocks,
            )?
        } else {
            crate::replay::mysql_validate_witness(
                event["database"].as_str(),
                raw,
                raw,
                surface,
                rules,
                clocks,
            )?
        };
        ensure!(
            report.passed(),
            "Source SQL value contract preflight failed"
        );
        checked.extend(report.evaluated);
        return Ok(checked);
    }
    let values = values(surface, event, raw)?;
    let mut checked = BTreeSet::new();
    for (key, value) in values {
        let selected = selected(rules, &key);
        if selected.is_empty() {
            continue;
        }
        checked.extend(compare(&value, &value, &selected, clocks)?);
    }
    Ok(checked)
}

pub(super) fn compare_pair(
    surface: Surface,
    event: &Value,
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    native: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<usize> {
    compare_pair_with_time_copies(surface, event, source, target, rules, native, clocks, None)
}

#[allow(clippy::too_many_arguments)] // Complete protected envelopes and their selected owners stay together.
pub(super) fn compare_pair_with_time_copies(
    surface: Surface,
    event: &Value,
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    native: &[&CompiledNativeRule],
    clocks: AnchorClocks,
    copies: Option<(&crate::value_contract::time_copies::TimeCopyStore, &str)>,
) -> Result<usize> {
    if protocol(event) == Some(Protocol::Redis)
        && rules
            .iter()
            .any(|rule| matches!(rule.rule.slot, crate::policy::Slot::RedisValue(_)))
    {
        return if copies.is_some() {
            super::redis_fields::pair_with_time_copies(
                surface, event, source, target, rules, clocks, copies,
            )
        } else {
            super::redis_fields::pair(surface, event, source, target, rules, clocks)
        };
    }
    if protocol(event) == Some(Protocol::Mysql) {
        let report = if surface == Surface::DependencyRequest {
            let candidate = if let Some((store, case)) = copies {
                crate::replay::mysql_validate_contract_candidate_with_time_copies(
                    event["database"].as_str(),
                    source,
                    target,
                    rules,
                    native,
                    clocks,
                    store,
                    case,
                )?
            } else {
                crate::replay::mysql_validate_contract_candidate(
                    event["database"].as_str(),
                    source,
                    target,
                    rules,
                    native,
                    clocks,
                )?
            };
            let Some(report) = candidate else {
                return Ok(0);
            };
            report
        } else {
            crate::replay::mysql_validate_witness(
                event["database"].as_str(),
                source,
                target,
                surface,
                rules,
                clocks,
            )?
        };
        ensure!(
            report.passed(),
            "SQL value witness failed: {}",
            serde_json::to_string(&report.differences)?
        );
        return Ok(report.evaluated.len());
    }
    let expected = values(surface, event, source)?;
    let actual = values(surface, event, target)?;
    let allowed = expected
        .iter()
        .filter(|(key, _)| !selected(rules, key).is_empty())
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis if surface == Surface::DependencyRequest => {
            let source: Vec<Vec<u8>> = serde_json::from_slice(source)?;
            let target: Vec<Vec<u8>> = serde_json::from_slice(target)?;
            let key = target.first().context("Target Redis key is missing")?;
            if selected(rules, key).is_empty() {
                // Search edges can contain another command's key in the same
                // resource/operation scope. It supplies no Target validation.
                return Ok(0);
            }
            let index = super::value_index(event, source.len())?;
            ensure!(
                source.len() == target.len(),
                "unselected Redis argument inventory differs: Source {}, Target {}",
                source.len(),
                target.len()
            );
            for (i, (before, after)) in source.iter().zip(&target).enumerate() {
                ensure!(
                    i == index || before == after,
                    "unselected Redis key/options/arguments differ at argument {i} (Source {} bytes, Target {} bytes)",
                    before.len(),
                    after.len()
                );
            }
        }
        Protocol::Redis => (),
        Protocol::Memcached => {
            crate::replay::memcached_validate_witness(source, target, surface, &allowed, clocks)?
        }
        Protocol::Http => {
            crate::replay::http_validate_contract_witness(source, target, surface, native, clocks)?
        }
        _ => anyhow::bail!("selected protocol requires its native envelope validation adapter"),
    }
    ensure!(
        expected.len() == actual.len(),
        "dependency value-slot inventory changed"
    );
    let mut count = 0;
    for ((key, source), (actual_key, target)) in expected.iter().zip(&actual) {
        ensure!(key == actual_key, "dependency value-slot identity changed");
        let selected = selected(rules, key);
        if selected.is_empty() {
            ensure!(source == target, "unselected dependency payload changed");
            continue;
        }
        if surface == Surface::DependencyResponse {
            let delivered = encoded::materialize(source, &selected, clocks)?;
            ensure!(
                &delivered == target,
                "derived delivery changed bytes outside the same rule's explicit delivery effects"
            );
            count += 1;
        } else if !compare(source, target, &selected, clocks)?.is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

fn selected<'a>(rules: &[&'a CompiledRule], key: &[u8]) -> Vec<&'a CompiledRule> {
    rules
        .iter()
        .copied()
        .filter(|rule| {
            rule.rule
                .selector
                .key
                .as_ref()
                .is_none_or(|selector| selector.matches(key))
        })
        .collect()
}

pub(in crate::rewrite::unified_rule) fn values(
    surface: Surface,
    event: &Value,
    raw: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis
            if surface == Surface::DependencyResponse
                && crate::replay::redis_bulk_payload(raw)?.is_none() =>
        {
            Ok(vec![])
        }
        Protocol::Redis => Ok(vec![(
            super::arguments(event)?
                .into_iter()
                .next()
                .context("Redis key is missing")?,
            super::redis_payload(surface, event, raw)?,
        )]),
        Protocol::Memcached => crate::memcached::value_slot::witness_values(
            raw,
            surface == Surface::DependencyResponse,
        ),
        Protocol::Http => Ok(crate::replay::http_witness_value(raw, surface)?
            .map(|payload| vec![(Vec::new(), payload)])
            .unwrap_or_default()),
        _ => anyhow::bail!("selected protocol requires its native value-slot extractor"),
    }
}

fn compare(
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    let report = encoded::compare(source, target, rules, clocks)?;
    ensure!(
        report.passed(),
        "unified contract preflight failed: {}",
        serde_json::to_string(&report.differences)?
    );
    Ok(report.evaluated)
}

fn database_matches(database: &Database, observed: &Value) -> bool {
    match database {
        Database::Index(index) => observed.as_i64() == Some(*index),
        Database::Name(name) => observed.as_str() == Some(name),
    }
}
