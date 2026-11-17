use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use super::inventory;
use super::model::RewriteState;
use crate::RecordingApi;

const MAX_HISTORICAL_RECORDING_RUNS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordingPublication {
    Missing,
    Running,
    Finalized,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RecordingProgress {
    pub(super) apis: usize,
    pub(super) published_cases: usize,
    pub(super) failed_cases: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordingStatus {
    pub(super) publication: RecordingPublication,
    pub(super) progress: RecordingProgress,
}

pub(super) fn validate_standard_recording(target_root: &Path, state: &RewriteState) -> Result<()> {
    let scope = standard_recording_scope(target_root, &state.recording_run_id)?;
    ensure!(
        scope == inventory::recording_scope(state) || scope == state.recording_apis,
        "standard recording scope does not match requested rewrite scope"
    );
    Ok(())
}

pub(super) fn standard_recording_scope(target_root: &Path, run_id: &str) -> Result<Vec<String>> {
    let report: StandardRecordingManifest = read_json(&recording_manifest(target_root, run_id))?;
    ensure!(
        report.status == "completed",
        "standard recording is not completed"
    );
    ensure!(
        report.published_cases > 0,
        "standard recording published no cases"
    );
    Ok(report.recording_apis)
}

pub(super) fn standard_recording_publication(
    target_root: &Path,
    run_id: &str,
) -> Result<RecordingPublication> {
    Ok(standard_recording_status(target_root, run_id)?.publication)
}

pub(super) fn standard_recording_status(
    target_root: &Path,
    run_id: &str,
) -> Result<RecordingStatus> {
    let path = recording_manifest(target_root, run_id);
    if !path.is_file() {
        return Ok(RecordingStatus {
            publication: RecordingPublication::Missing,
            progress: RecordingProgress::default(),
        });
    }
    let manifest: StandardRecordingManifest = read_json(&path)?;
    Ok(RecordingStatus {
        publication: publication(&manifest.status)?,
        progress: RecordingProgress {
            apis: manifest.observed_api_count,
            published_cases: manifest.published_cases,
            failed_cases: manifest.failed_cases,
        },
    })
}

pub(super) fn standard_recording_apis(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Vec<String>> {
    standard_recording_apis_for_scope(
        target_root,
        &state.recording_run_id,
        inventory::recording_scope(state),
    )
}

pub(super) fn standard_recording_apis_for_scope(
    target_root: &Path,
    run_id: &str,
    requested: Vec<String>,
) -> Result<Vec<String>> {
    if !requested.is_empty() {
        return validate_api_members(&recording_run(target_root, run_id), requested);
    }
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    recording_apis_with_config(target_root, run_id, requested, &config)
}

pub(super) fn recording_apis_with_config(
    target_root: &Path,
    run_id: &str,
    requested: Vec<String>,
    config: &crate::config::AppConfig,
) -> Result<Vec<String>> {
    let case_source = recording_run(target_root, run_id);
    let apis = if requested.is_empty() {
        discover_recorded_apis_from_config(config, &case_source)?
    } else {
        requested
    };
    validate_api_members(&case_source, apis)
}

fn validate_api_members(case_source: &Path, mut apis: Vec<String>) -> Result<Vec<String>> {
    apis.sort();
    apis.dedup();
    ensure!(
        !apis.is_empty(),
        "standard recording contains no API inventory"
    );
    let selectors = apis
        .iter()
        .map(|api| api.parse::<RecordingApi>())
        .collect::<Result<Vec<_>>>()?;
    crate::case_group::validate_recording_api_cases(case_source, &selectors)
        .context("standard recording has no canonical case member for its API inventory")?;
    Ok(apis)
}

pub(super) fn standard_recording_api_case_counts(
    target_root: &Path,
    state: &RewriteState,
    apis: &[String],
) -> Result<BTreeMap<String, u64>> {
    let case_source = recording_run(target_root, &state.recording_run_id);
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    let discovered = discover_recorded_api_counts_from_config(&config, &case_source)?;
    apis.iter()
        .map(|api| {
            let cases = discovered
                .get(api)
                .copied()
                .with_context(|| format!("standard recording API {api:?} published no cases"))?;
            Ok((api.clone(), cases))
        })
        .collect()
}

pub(super) fn recording_rejection(error: &anyhow::Error) -> String {
    public_rejection(
        error,
        &[
            "standard recording is not completed",
            "standard recording scope does not match requested rewrite scope",
            "standard recording contains no API inventory",
            "standard recording published no cases",
        ],
        "standard recording evidence is unreadable or invalid",
    )
}

fn discover_recorded_apis_from_config(
    config: &crate::config::AppConfig,
    case_source: &Path,
) -> Result<Vec<String>> {
    Ok(
        discover_recorded_api_counts_from_config(config, case_source)?
            .into_keys()
            .collect(),
    )
}

fn discover_recorded_api_counts_from_config(
    config: &crate::config::AppConfig,
    case_source: &Path,
) -> Result<BTreeMap<String, u64>> {
    let mut request_files = Vec::new();
    collect_request_files(case_source, case_source, &mut request_files)?;
    ensure!(
        request_files.len() <= 100_000,
        "standard recording API inventory exceeds the supported case bound"
    );
    let mut apis = BTreeMap::<String, u64>::new();
    for path in request_files {
        let request: StandardCaseRequest = read_json(&path)?;
        let uri = request
            .uri
            .parse::<hyper::Uri>()
            .with_context(|| format!("recorded request has invalid URI in {}", path.display()))?;
        let pattern = configured_pattern(config, uri.path())
            .or(request.api_pattern)
            .unwrap_or_else(|| uri.path().to_string());
        let api = format!("{} {pattern}", request.method).parse::<RecordingApi>()?;
        let count = apis.entry(api.to_string()).or_default();
        *count = count.saturating_add(1);
    }
    Ok(apis)
}

pub(super) fn standard_recording_observed_apis(
    target_root: &Path,
    run_id: &str,
) -> Result<Vec<String>> {
    observed_apis(&recording_run(target_root, run_id))
}

pub(super) fn historical_standard_recording_observed_apis(
    target_root: &Path,
    excluded_run_id: &str,
) -> Result<Vec<String>> {
    let root = target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings");
    let mut entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries.collect::<std::io::Result<Vec<_>>>()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect recordings {}", root.display()));
        }
    };
    entries.retain(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()));
    entries.sort_by_key(std::fs::DirEntry::file_name);
    entries.reverse();
    entries.truncate(MAX_HISTORICAL_RECORDING_RUNS);

    let mut apis = std::collections::BTreeSet::new();
    for entry in entries {
        if entry.file_name().to_string_lossy() == excluded_run_id {
            continue;
        }
        let Ok(manifest) =
            read_json::<StandardRecordingManifest>(&entry.path().join("recording-run.json"))
        else {
            continue;
        };
        if manifest.status != "completed" || manifest.published_cases == 0 {
            continue;
        }
        let Ok(observed) = observed_apis(&entry.path()) else {
            continue;
        };
        apis.extend(observed);
    }
    Ok(apis.into_iter().collect())
}

fn observed_apis(case_source: &Path) -> Result<Vec<String>> {
    let mut request_files = Vec::new();
    collect_request_files(case_source, case_source, &mut request_files)?;
    ensure!(
        request_files.len() <= 100_000,
        "standard recording API inventory exceeds the supported case bound"
    );
    request_files
        .into_iter()
        .map(|path| {
            let request: StandardCaseRequest = read_json(&path)?;
            let uri = request.uri.parse::<hyper::Uri>().with_context(|| {
                format!("recorded request has invalid URI in {}", path.display())
            })?;
            let api = format!(
                "{} {}",
                request.method.trim().to_ascii_uppercase(),
                uri.path()
            )
            .parse::<RecordingApi>()?;
            Ok(api.to_string())
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()
        .map(|apis| apis.into_iter().collect())
}

fn configured_pattern(config: &crate::config::AppConfig, path: &str) -> Option<String> {
    config
        .http_gateway
        .case_path_patterns
        .iter()
        .find(|pattern| crate::path_pattern::matches_path_pattern(pattern, path))
        .cloned()
}

fn collect_request_files(
    case_source: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("failed to inspect recording cases {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if directory == case_source
                && matches!(
                    entry.file_name().to_str(),
                    Some("failed" | "staging" | ".replay" | ".partial" | ".truncated")
                )
            {
                continue;
            }
            collect_request_files(case_source, &path, output)?;
        } else if file_type.is_file() && entry.file_name() == "request.json" {
            output.push(path);
        }
    }
    Ok(())
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
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(run_id)
}

pub(super) fn recording_manifest(target_root: &Path, run_id: &str) -> PathBuf {
    recording_run(target_root, run_id).join("recording-run.json")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read generated evidence {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid generated evidence {}", path.display()))
}

fn publication(status: &str) -> Result<RecordingPublication> {
    Ok(match status {
        "running" => RecordingPublication::Running,
        "completed" | "failed" => RecordingPublication::Finalized,
        other => anyhow::bail!("generated recording manifest has unsupported status {other:?}"),
    })
}

#[derive(Debug, Deserialize)]
struct StandardRecordingManifest {
    status: String,
    recording_apis: Vec<String>,
    #[serde(default)]
    observed_api_count: usize,
    published_cases: usize,
    #[serde(default)]
    failed_cases: usize,
}

#[derive(Debug, Deserialize)]
struct StandardCaseRequest {
    method: String,
    uri: String,
    #[serde(default)]
    api_pattern: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_recording_publication_accepts_structured_errors() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "20260803021953";
        let run = recording_run(target.path(), run_id);
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(
            run.join("recording-run.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": "running",
                "recording_apis": [],
                "published_cases": 651,
                "failed_cases": 1,
                "errors": [{
                    "rule_name": "http-rule",
                    "case_id": "f036616f-aa65-4938-b805-64fc26ef5165",
                    "reason": "dependency_replay_unsafe"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            standard_recording_publication(target.path(), run_id).unwrap(),
            RecordingPublication::Running
        );
    }

    #[test]
    fn unscoped_recording_inventory_uses_recorded_patterns_and_legacy_config_fallback() {
        let source = tempfile::tempdir().unwrap();
        let first = source.path().join("apis/api-a/case-1");
        let second = source.path().join("apis/api-b/case-2");
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
            ..Default::default()
        }];
        config.http_gateway.case_path_patterns = vec!["/widgets/*".to_string()];

        assert_eq!(
            discover_recorded_apis_from_config(&config, source.path()).unwrap(),
            vec!["GET /users/*", "POST /widgets/*"]
        );
    }

    #[test]
    fn current_config_pattern_recanonicalizes_a_recorded_exact_pattern() {
        let source = tempfile::tempdir().unwrap();
        let case = source.path().join("apis/api-users/case-1");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"GET","uri":"/users/1","api_pattern":"/users/1"}"#,
        )
        .unwrap();
        let mut config = crate::config::AppConfig::default();
        config.http_gateway.case_path_patterns = vec!["/users/*".to_string()];

        assert_eq!(
            discover_recorded_apis_from_config(&config, source.path()).unwrap(),
            vec!["GET /users/*"]
        );
    }

    #[test]
    fn standard_recording_inventory_excludes_quarantined_and_staging_cases() {
        let source = tempfile::tempdir().unwrap();
        for relative in [
            "apis/api/case-published",
            "failed/api/case-quarantined",
            "staging/api/case-staging",
        ] {
            let case = source.path().join(relative);
            std::fs::create_dir_all(&case).unwrap();
            std::fs::write(
                case.join("request.json"),
                r#"{"method":"GET","uri":"/users/1","api_pattern":"/users/*","matched_rule":"api"}"#,
            )
            .unwrap();
        }

        assert_eq!(
            discover_recorded_api_counts_from_config(
                &crate::config::AppConfig::default(),
                source.path(),
            )
            .unwrap(),
            BTreeMap::from([("GET /users/*".to_string(), 1)])
        );
    }

    #[test]
    fn standard_recording_validation_accepts_quarantined_case_errors() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "20260803021953";
        let run = recording_run(target.path(), run_id);
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(
            run.join("recording-run.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": "completed",
                "recording_apis": ["GET /api"],
                "published_cases": 667,
                "failed_cases": 1,
                "errors": [{
                    "rule_name": "http-rule",
                    "case_id": "f036616f-aa65-4938-b805-64fc26ef5165",
                    "reason": "dependency_replay_unsafe"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut state = crate::rewrite::test_state();
        state.recording_run_id = run_id.to_string();

        validate_standard_recording(target.path(), &state).unwrap();
    }
}
