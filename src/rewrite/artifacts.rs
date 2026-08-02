use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use serde::Deserialize;

use super::inventory;
use super::model::RewriteState;
use crate::{ManagedRecordingOperation, RecordingApi, resolve_recording_api_member};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordingPublication {
    Missing,
    Running,
    Finalized,
}

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
        report.recording_apis == inventory::recording_scope(state),
        "standard recording scope does not match requested rewrite scope"
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

pub(super) fn standard_recording_publication(
    target_root: &Path,
    run_id: &str,
) -> Result<RecordingPublication> {
    manifest_publication::<StandardRecordingManifest>(
        &recording_manifest(target_root, run_id),
        |manifest| manifest.status.as_str(),
    )
}

pub(super) fn standard_recording_apis(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Vec<String>> {
    let case_source = recording_run(target_root, &state.recording_run_id);
    let requested = inventory::recording_scope(state);
    let mut apis = if requested.is_empty() {
        discover_recorded_apis(target_root, &case_source)?
    } else {
        requested
    };
    apis.sort();
    apis.dedup();
    ensure!(
        !apis.is_empty(),
        "standard recording contains no API inventory"
    );
    for api in &apis {
        let api = api.parse::<RecordingApi>()?;
        resolve_recording_api_member(&case_source, &api).with_context(|| {
            format!("standard recording has no canonical case member for {api}")
        })?;
    }
    Ok(apis)
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

pub(super) fn comparison_recording_publication(
    target_root: &Path,
    run_id: &str,
) -> Result<RecordingPublication> {
    manifest_publication::<ComparisonRecordingManifest>(
        &comparison_manifest(target_root, run_id),
        |manifest| manifest.status.as_str(),
    )
}

pub(super) fn compatible_recording_input(
    target_root: &Path,
    requested_apis: &[String],
    excluded_run_id: Option<&str>,
) -> Result<Option<PathBuf>> {
    let root = target_root.join(".traffic-e2e/artifacts/recordings");
    let mut runs = match std::fs::read_dir(&root) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect recordings {}", root.display()));
        }
    };
    runs.sort_by_key(std::fs::DirEntry::file_name);
    for entry in runs.into_iter().rev() {
        let run_id = entry.file_name();
        let run_id = run_id.to_string_lossy();
        if excluded_run_id == Some(run_id.as_ref()) || !entry.path().is_dir() {
            continue;
        }
        let manifest = entry.path().join("recording-run.json");
        let Ok(report) = read_json::<StandardRecordingManifest>(&manifest) else {
            continue;
        };
        let scope_matches = if requested_apis.is_empty() {
            report.recording_apis.is_empty()
        } else {
            requested_apis.iter().all(|api| {
                api.parse::<RecordingApi>()
                    .is_ok_and(|api| resolve_recording_api_member(&entry.path(), &api).is_ok())
            })
        };
        if report.status == "completed"
            && report.published_cases > 0
            && report.failed_cases == 0
            && report.errors.is_empty()
            && scope_matches
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

pub(super) fn recording_rejection(error: &anyhow::Error) -> String {
    public_rejection(
        error,
        &[
            "standard recording is not completed",
            "standard recording scope does not match requested rewrite scope",
            "standard recording contains no API inventory",
            "standard recording published no cases",
            "standard recording is dirty",
        ],
        "standard recording evidence is unreadable or invalid",
    )
}

fn discover_recorded_apis(target_root: &Path, case_source: &Path) -> Result<Vec<String>> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    discover_recorded_apis_from_config(&config, case_source)
}

fn discover_recorded_apis_from_config(
    config: &crate::config::AppConfig,
    case_source: &Path,
) -> Result<Vec<String>> {
    let mut request_files = Vec::new();
    collect_request_files(case_source, &mut request_files)?;
    ensure!(
        request_files.len() <= 100_000,
        "standard recording API inventory exceeds the supported case bound"
    );
    let mut apis = BTreeSet::new();
    for path in request_files {
        let request: StandardCaseRequest = read_json(&path)?;
        let uri = request
            .uri
            .parse::<hyper::Uri>()
            .with_context(|| format!("recorded request has invalid URI in {}", path.display()))?;
        let pattern = request.api_pattern.unwrap_or_else(|| {
            configured_pattern(config, request.matched_rule.as_deref(), uri.path())
                .unwrap_or_else(|| uri.path().to_string())
        });
        let api = format!("{} {pattern}", request.method).parse::<RecordingApi>()?;
        apis.insert(api.to_string());
    }
    Ok(apis.into_iter().collect())
}

fn configured_pattern(
    config: &crate::config::AppConfig,
    matched_rule: Option<&str>,
    path: &str,
) -> Option<String> {
    let patterns = if config.http_gateway.rules.is_empty() && matched_rule == Some("default") {
        None
    } else {
        config.http_gateway.rules.iter().find(|rule| {
            rule.name.as_deref().unwrap_or("unnamed") == matched_rule.unwrap_or_default()
        })
    }
    .map(|rule| &rule.case_path_patterns)?;
    patterns
        .iter()
        .find(|pattern| crate::path_pattern::matches_path_pattern(pattern, path))
        .cloned()
}

fn collect_request_files(root: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root)
        .with_context(|| format!("failed to inspect recording cases {}", root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_request_files(&path, output)?;
        } else if file_type.is_file() && entry.file_name() == "request.json" {
            output.push(path);
        }
    }
    Ok(())
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

fn manifest_publication<T>(
    path: &Path,
    status: impl FnOnce(&T) -> &str,
) -> Result<RecordingPublication>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.is_file() {
        return Ok(RecordingPublication::Missing);
    }
    let manifest: T = read_json(path)?;
    Ok(match status(&manifest) {
        "running" => RecordingPublication::Running,
        "completed" | "failed" => RecordingPublication::Finalized,
        other => anyhow::bail!("generated recording manifest has unsupported status {other:?}"),
    })
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
struct StandardCaseRequest {
    method: String,
    uri: String,
    #[serde(default)]
    api_pattern: Option<String>,
    #[serde(default)]
    matched_rule: Option<String>,
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

    #[test]
    fn recording_input_reuses_only_the_newest_compatible_finalized_run() {
        let target = tempfile::tempdir().unwrap();
        let recordings = target.path().join(".traffic-e2e/artifacts/recordings");
        let valid = recordings.join("20260802000001");
        let newer_dirty = recordings.join("20260802000002");
        std::fs::create_dir_all(&valid).unwrap();
        std::fs::create_dir_all(&newer_dirty).unwrap();
        std::fs::write(
            valid.join("recording-run.json"),
            r#"{"status":"completed","recording_apis":[],"published_cases":3,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        std::fs::write(
            newer_dirty.join("recording-run.json"),
            r#"{"status":"completed","recording_apis":["GET /api"],"published_cases":3,"failed_cases":1,"errors":["failed"]}"#,
        )
        .unwrap();

        assert_eq!(
            compatible_recording_input(target.path(), &[], None).unwrap(),
            Some(valid.clone())
        );
        assert_eq!(
            compatible_recording_input(target.path(), &[], Some("20260802000001")).unwrap(),
            None
        );
    }

    #[test]
    fn unscoped_recording_inventory_uses_recorded_patterns_and_legacy_config_fallback() {
        let source = tempfile::tempdir().unwrap();
        let first = source.path().join("api-a/case-1");
        let second = source.path().join("api-b/case-2");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(
            first.join("request.json"),
            r#"{"method":"GET","uri":"/users/1","api_pattern":"/users/*","matched_rule":"api"}"#,
        )
        .unwrap();
        std::fs::write(
            second.join("request.json"),
            r#"{"method":"POST","uri":"/widgets/2","matched_rule":"api"}"#,
        )
        .unwrap();
        let mut config = crate::config::AppConfig::default();
        config.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
            name: Some("api".to_string()),
            case_path_patterns: vec!["/widgets/*".to_string()],
            ..Default::default()
        }];

        assert_eq!(
            discover_recorded_apis_from_config(&config, source.path()).unwrap(),
            vec!["GET /users/*", "POST /widgets/*"]
        );
    }
}
