//! Source registration delegates protocol interpretation to installed native providers.
use crate::replay::{self, RecordedProxyError, ReplayTarget, TargetKey, native};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
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
    for (line, record) in records {
        if skip.contains(&line) {
            continue;
        }
        match record {
            DependencyRecord::Native(event) => {
                validate_installed_provider(&event, &native.providers)?;
                native.register(
                    &event,
                    source,
                    case,
                    line,
                    targets,
                    &crate::request_headers::SourceSecrets::new(path),
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
