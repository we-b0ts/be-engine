//! Protocol admission and immutable envelopes stay outside the encoded value core.
use crate::{
    policy::{CompiledNativeRule, Database, Protocol, Surface},
    policy_evidence::WitnessRef,
    value_contract::json::AnchorClocks,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub(in crate::rewrite::unified_rule) fn protocol(event: &Value) -> Option<Protocol> {
    match event["event_type"].as_str()? {
        "redis_exchange" => Some(Protocol::Redis),
        "memcached_exchange" => Some(Protocol::Memcached),
        "http_exchange" => Some(Protocol::Http),
        "mysql_exchange" => Some(Protocol::Mysql),
        _ => None,
    }
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
    crate::policy::runtime::mysql_native_witness_matches(event, rule)
}

pub(in crate::rewrite) fn source_witness(
    surface: Surface,
    event: &Value,
    key_context: &Path,
) -> Result<Vec<u8>> {
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis if surface == Surface::DependencyRequest => {
            Ok(serde_json::to_vec(&super::arguments(event)?)?)
        }
        Protocol::Redis => super::capture(&event["response"]),
        Protocol::Memcached => {
            anyhow::bail!("Memcached recording has no installed protocol implementation")
        }
        Protocol::Mysql => crate::protocols::replay::mysql_source_witness(event, surface),
        Protocol::Http => {
            crate::protocols::replay::http_source_witness(event, surface, key_context)
        }
    }
}

pub(in crate::rewrite::unified_rule) fn validate_metadata(
    witness: &WitnessRef,
    event: &Value,
) -> Result<()> {
    if protocol(event) == Some(Protocol::Http) {
        return crate::protocols::replay::http_witness_metadata_matches(event, &witness.metadata);
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
    native: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<BTreeSet<String>> {
    ensure!(
        surface == Surface::DependencyRequest && protocol(event) == Some(Protocol::Mysql),
        "native value preflight requires a MySQL request"
    );
    let report = crate::protocols::replay::mysql_validate_contract_witness(
        event["database"].as_str(),
        raw,
        raw,
        &[],
        native,
        clocks,
    )?;
    ensure!(
        report.passed(),
        "Source native SQL contract preflight failed"
    );
    Ok(report.evaluated)
}

pub(super) fn compare_pair(
    surface: Surface,
    event: &Value,
    source: &[u8],
    target: &[u8],
    native: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<usize> {
    ensure!(
        surface == Surface::DependencyRequest && protocol(event) == Some(Protocol::Mysql),
        "native value preflight requires a MySQL request"
    );
    let Some(report) = crate::protocols::replay::mysql_validate_contract_candidate(
        event["database"].as_str(),
        source,
        target,
        &[],
        native,
        clocks,
    )?
    else {
        return Ok(0);
    };
    ensure!(
        report.passed(),
        "native SQL witness failed: {}",
        serde_json::to_string(&report.differences)?
    );
    Ok(report.evaluated.len())
}

pub(in crate::rewrite) fn values(
    surface: Surface,
    event: &Value,
    raw: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    match protocol(event).context("unsupported dependency event")? {
        Protocol::Redis
            if surface == Surface::DependencyResponse
                && crate::policy::runtime::redis_bulk_payload(raw)?.is_none() =>
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
        Protocol::Memcached => {
            anyhow::bail!("Memcached recording has no installed protocol implementation")
        }
        Protocol::Http => Ok(crate::protocols::replay::http_witness_value(raw, surface)?
            .map(|payload| vec![(Vec::new(), payload)])
            .unwrap_or_default()),
        _ => anyhow::bail!("selected protocol requires its native value-slot extractor"),
    }
}

fn database_matches(database: &Database, observed: &Value) -> bool {
    match database {
        Database::Index(index) => observed.as_i64() == Some(*index),
        Database::Name(name) => observed.as_str() == Some(name),
    }
}
