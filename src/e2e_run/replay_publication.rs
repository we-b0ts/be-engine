//! Keep Replay evidence inside the atomically published runner snapshot.
use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{model::ActiveRunState, store};
use crate::replay::report::{build_dependency_evidence, dependency_evidence_path};

pub(super) fn prepare(
    state: &ActiveRunState,
    old: &Path,
    staging: &Path,
    published: &Path,
) -> Result<ActiveRunState> {
    let source = if let Ok(relative) = state.replay_report.strip_prefix(old) {
        staging.join(relative)
    } else {
        state.replay_report.clone()
    };
    if !source.is_file() {
        ensure!(
            !state.replay_finalized,
            "finalized Replay evidence is missing at {}; recover with fresh Replay before publication",
            source.display()
        );
        return Ok(state.clone());
    }
    let destination = staging.join("reports/replay-report.json");
    fs::create_dir_all(destination.parent().expect("report directory"))?;
    if source != destination {
        fs::copy(&source, &destination).context("failed to stage runner-owned Replay evidence")?;
    }
    let sidecar = dependency_evidence_path(&destination);
    let source_sidecar = dependency_evidence_path(&source);
    if source_sidecar.is_file() {
        if source_sidecar != sidecar {
            fs::copy(source_sidecar, &sidecar)?;
        }
    } else {
        // This is a deterministic projection of the complete report, never a
        // substitute for missing target observations or recorded exchanges.
        let report: Value = serde_json::from_slice(&fs::read(&destination)?)?;
        store::write_json(&sidecar, &build_dependency_evidence(&report))?;
    }
    let replay_report = old.join("reports/replay-report.json");
    let aggregates = std::iter::once(state.aggregate_report.clone())
        .chain(
            state
                .apis
                .iter()
                .map(|api| api.report_dir.join("aggregate.json")),
        )
        .collect::<BTreeSet<_>>();
    for path in aggregates {
        let relative = path
            .strip_prefix(old)
            .context("aggregate escaped its run directory")?;
        let physical = staging.join(relative);
        let bytes = match fs::read(&physical) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut aggregate: Value = serde_json::from_slice(&bytes)?;
        if let Some(reports) = aggregate.get_mut("reports").and_then(Value::as_array_mut) {
            for report in reports {
                if report.get("path").and_then(Value::as_str) == state.replay_report.to_str()
                    || report.get("path").and_then(Value::as_str) == replay_report.to_str()
                {
                    report["path"] = Value::String(
                        published
                            .join("reports/replay-report.json")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        store::write_json(&physical, &aggregate)?;
    }
    let mut output = state.clone();
    output.replay_report = replay_report;
    Ok(output)
}

#[cfg(test)]
mod tests;
