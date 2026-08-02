use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use serde::Deserialize;

use super::model::RewriteState;
use crate::ManagedRecordingOperation;

pub(super) fn allocate_run_id(
    target_root: &Path,
    operation: ManagedRecordingOperation,
) -> Result<String> {
    allocate_run_id_excluding(target_root, operation, &[])
}

pub(super) fn allocate_run_id_excluding(
    target_root: &Path,
    operation: ManagedRecordingOperation,
    excluded: &[&str],
) -> Result<String> {
    let now = Utc::now().naive_utc();
    for offset in 0..120 {
        let run_id = (now + Duration::seconds(offset))
            .format("%Y%m%d%H%M%S")
            .to_string();
        if excluded.contains(&run_id.as_str()) {
            continue;
        }
        let run = match operation {
            ManagedRecordingOperation::Record => recording_run(target_root, &run_id),
            ManagedRecordingOperation::RecordComparison => comparison_run(target_root, &run_id),
        };
        if !run.exists() {
            return Ok(run_id);
        }
    }
    anyhow::bail!("failed to allocate a unique recording run id")
}

pub(super) fn validate_standard_recording(target_root: &Path, state: &RewriteState) -> Result<()> {
    let report: StandardRecordingManifest =
        read_json(&recording_manifest(target_root, &state.recording_run_id))?;
    ensure!(
        report.status == "completed",
        "standard recording is not completed"
    );
    ensure!(
        report.recording_apis == vec![state.api.clone()],
        "standard recording scope does not match active rewrite API"
    );
    ensure!(
        report.published_cases > 0,
        "standard recording published no cases"
    );
    ensure!(
        report.failed_cases == 0 && report.errors.is_empty(),
        "standard recording is dirty"
    );
    Ok(())
}

pub(super) fn validate_comparison_recording(
    target_root: &Path,
    state: &RewriteState,
) -> Result<()> {
    let run_id = state
        .comparison_run_id
        .as_deref()
        .context("comparison phase has no run id")?;
    let report: ComparisonRecordingManifest = read_json(&comparison_manifest(target_root, run_id))?;
    ensure!(
        report.status == "completed" && report.ready,
        "comparison recording is not finalized and ready"
    );
    ensure!(
        report.recording_apis == vec![state.api.clone()],
        "comparison recording scope does not match active rewrite API"
    );
    ensure!(
        report.counts.published > 0,
        "comparison recording published no cases"
    );
    ensure!(
        report.counts.failed == 0 && report.errors.is_empty(),
        "comparison recording is dirty"
    );
    Ok(())
}

pub(super) fn recording_rejection(error: &anyhow::Error) -> String {
    public_rejection(
        error,
        &[
            "standard recording is not completed",
            "standard recording scope does not match active rewrite API",
            "standard recording published no cases",
            "standard recording is dirty",
        ],
        "standard recording evidence is unreadable or invalid",
    )
}

pub(super) fn comparison_rejection(error: &anyhow::Error) -> String {
    public_rejection(
        error,
        &[
            "comparison recording is not finalized and ready",
            "comparison recording scope does not match active rewrite API",
            "comparison recording published no cases",
            "comparison recording is dirty",
        ],
        "comparison recording evidence is unreadable or invalid",
    )
}

fn public_rejection(error: &anyhow::Error, allowed: &[&str], fallback: &str) -> String {
    let message = error.to_string();
    allowed
        .iter()
        .find(|candidate| message == **candidate)
        .copied()
        .unwrap_or(fallback)
        .to_string()
}

pub(super) fn recording_run(target_root: &Path, run_id: &str) -> PathBuf {
    target_root
        .join(".traffic-e2e/artifacts/recordings")
        .join(run_id)
}

pub(super) fn comparison_run(target_root: &Path, run_id: &str) -> PathBuf {
    target_root
        .join(".traffic-e2e/artifacts/comparison-recordings")
        .join(run_id)
}

pub(super) fn recording_manifest(target_root: &Path, run_id: &str) -> PathBuf {
    recording_run(target_root, run_id).join("recording-run.json")
}

pub(super) fn comparison_manifest(target_root: &Path, run_id: &str) -> PathBuf {
    comparison_run(target_root, run_id).join("comparison-recording-run.json")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read generated evidence {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid generated evidence {}", path.display()))
}

#[derive(Debug, Deserialize)]
struct StandardRecordingManifest {
    status: String,
    recording_apis: Vec<String>,
    published_cases: usize,
    failed_cases: usize,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ComparisonRecordingManifest {
    status: String,
    ready: bool,
    recording_apis: Vec<String>,
    counts: ComparisonRecordingCounts,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ComparisonRecordingCounts {
    published: usize,
    failed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_can_exclude_an_unpublished_reserved_run() {
        let target = tempfile::tempdir().unwrap();
        let reserved = allocate_run_id(target.path(), ManagedRecordingOperation::Record).unwrap();

        let replacement = allocate_run_id_excluding(
            target.path(),
            ManagedRecordingOperation::Record,
            &[&reserved],
        )
        .unwrap();

        assert_ne!(replacement, reserved);
    }
}
