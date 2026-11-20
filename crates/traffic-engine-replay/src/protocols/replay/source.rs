//! Source registration delegates protocol interpretation to installed native providers.
use crate::replay::{self, RecordedProxyError, ReplayTarget, TargetKey, native};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use traffic_protocol::connection::ReplaySessionStep;
use traffic_replay::ReplaySource;
pub mod preparation;
mod record;
pub use record::DependencyRecord;
pub mod global;
pub mod projection;

fn validate_installed_provider(
    event: &Value,
    providers: &crate::protocols::DependencyProviders,
) -> Result<()> {
    let kind = event["event_type"].as_str().unwrap_or_default();
    let requires_provider = event["capture"]["semantic_required"] == true
        || [
            "_exchange",
            "_connection",
            "_produce",
            "_fetch",
            "_delivery",
            "_pub_sub_push",
        ]
        .iter()
        .any(|suffix| kind.ends_with(suffix));
    if requires_provider {
        ensure!(
            providers.event_provider(event).is_some(),
            "recording event {kind:?} has no installed protocol implementation"
        );
    }
    Ok(())
}

pub fn validate_index_record(value: &Value) -> Result<()> {
    replay::dependencies::validate_outcome(value)?;
    let _: DependencyRecord = serde_json::from_value(value.clone())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn register_dependency_records(
    path: &Path,
    records: Vec<(usize, DependencyRecord)>,
    skip: &BTreeSet<usize>,
    source: ReplaySource,
    case: Option<&str>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    _rules: &[crate::BackgroundDependencyRuleConfig],
    cleanup: &BTreeSet<replay::RecordedReference>,
    native: &mut native::Inventory,
) -> Result<()> {
    ensure!(
        cleanup.is_empty(),
        "incomplete cleanup exchanges require an installed native lifecycle capability"
    );
    let plans = prepare_replay_scopes(&records, skip, source, &native.providers)?;
    for (line, record) in records {
        if skip.contains(&line) {
            continue;
        }
        match record {
            DependencyRecord::Native(event) => {
                validate_installed_provider(&event, &native.providers)?;
                let step = plans.get(&line).cloned();
                native.register_scoped(
                    &event,
                    source,
                    case,
                    line,
                    targets,
                    &crate::request_headers::SourceSecrets::new(path),
                    step,
                )?;
            }
            DependencyRecord::ProxyError(error) => anyhow::bail!(
                "unsafe dependency proxy error for {}: {}",
                error.protocol,
                error.error
            ),
            DependencyRecord::ConnectFailure => {}
        }
    }
    Ok(())
}

fn needs_replay_scope(
    record: &DependencyRecord,
    providers: &crate::protocols::DependencyProviders,
) -> bool {
    let DependencyRecord::Native(event) = record else {
        return false;
    };
    providers
        .event_provider(event)
        .and_then(|entry| entry.provider.native_protocol())
        .is_some_and(|provider| provider.has_replay_scope())
}

fn prepare_replay_scopes(
    records: &[(usize, DependencyRecord)],
    skip: &BTreeSet<usize>,
    source: ReplaySource,
    providers: &crate::protocols::DependencyProviders,
) -> Result<BTreeMap<usize, ReplaySessionStep>> {
    let mut scopes = BTreeMap::new();
    for (line, record) in records {
        let DependencyRecord::Native(event) = record else {
            continue;
        };
        if skip.contains(line) {
            continue;
        }
        let Some(entry) = providers.event_provider(event) else {
            continue;
        };
        let Some(provider) = entry
            .provider
            .native_protocol()
            .filter(|p| p.has_replay_scope())
        else {
            continue;
        };
        let (_, scope) = scopes
            .entry(entry.kind.as_str())
            .or_insert_with(|| (provider, Vec::new()));
        scope.push((*line, event.as_ref()));
    }
    let mut plans = BTreeMap::new();
    for (provider, scope) in scopes.into_values() {
        plans.extend(provider.prepare_replay_scope(source, &scope)?);
    }
    Ok(plans)
}

pub fn startup_records(
    path: &Path,
    index: &crate::dependency_index::FileIndex,
    reader: &mut crate::dependency_index::RecordReader,
) -> Result<Vec<(usize, DependencyRecord)>> {
    let mut records = BTreeMap::new();
    for (line, value) in &index.metadata {
        if value["event_type"] != "indexed_advertised_target" {
            records.insert(*line, serde_json::from_value(value.clone())?);
        }
    }
    for entry in index.records("redis") {
        let raw = reader.read(path, &index.stamp, &entry.location)?;
        records.insert(entry.location.line, serde_json::from_slice(&raw)?);
    }
    Ok(records.into_iter().collect())
}

#[cfg(test)]
mod tests;
