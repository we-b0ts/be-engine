use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use serde::Deserialize;

use super::inventory;
use super::model::RewriteState;
use crate::{ManagedRecordingOperation, RecordingApi};

const MAX_HISTORICAL_RECORDING_RUNS: usize = 256;

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
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    validate_standard_recording_with_process_outputs(target_root, state, &project.process_outputs)
}

fn validate_standard_recording_with_process_outputs(
    target_root: &Path,
    state: &RewriteState,
    process_outputs: &[crate::process_output::ProcessOutputConfig],
) -> Result<()> {
    let process_outputs = crate::process_output::configs_for_observation(
        process_outputs,
        crate::process_output::ProcessOutputObservation::BeforeShutdown,
    );
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
    crate::process_output::validate_capture_set(
        &process_outputs,
        crate::process_output::ProcessOutputCaptureSide::Source,
        &recording_run(target_root, &state.recording_run_id).join("process-outputs"),
        true,
    )?;
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
        crate::case_group::resolve_recording_api_seed_member(&case_source, &api).with_context(
            || format!("standard recording has no canonical case member for {api}"),
        )?;
    }
    if let Some(refresh) = &state.recording_refresh {
        ensure_required_apis_preserved(&refresh.required_apis, &apis)?;
    }
    Ok(apis)
}

fn ensure_required_apis_preserved(
    required_apis: &[String],
    recorded_apis: &[String],
) -> Result<()> {
    let missing = required_apis
        .iter()
        .filter(|required| !recorded_apis.contains(required))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(MissingRecordingApis(missing).into());
    }
    Ok(())
}

#[derive(Debug)]
struct MissingRecordingApis(Vec<String>);

impl std::fmt::Display for MissingRecordingApis {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Project only coordinator-owned API selectors, never a raw I/O error
        // or case path. Keep even a large inventory bounded in the action.
        let shown = self
            .0
            .iter()
            .take(16)
            .map(|api| api.chars().take(160).collect::<String>())
            .collect::<Vec<_>>();
        write!(
            formatter,
            "replacement recording lost previously published APIs: {}",
            shown.join(", ")
        )?;
        if self.0.len() > shown.len() {
            write!(formatter, " (and {} more)", self.0.len() - shown.len())?;
        }
        Ok(())
    }
}

impl std::error::Error for MissingRecordingApis {}

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
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let process_outputs =
        super::process_outputs::comparison_configs(state, &project.process_outputs);
    let process_output_root = comparison_run(target_root, run_id).join("process-outputs");
    crate::process_output::validate_capture_set(
        &process_outputs,
        crate::process_output::ProcessOutputCaptureSide::Source,
        &process_output_root.join("source"),
        true,
    )?;
    crate::process_output::validate_capture_set(
        &process_outputs,
        crate::process_output::ProcessOutputCaptureSide::Target,
        &process_output_root.join("target"),
        false,
    )?;
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

pub(super) fn recording_rejection(error: &anyhow::Error) -> String {
    if let Some(missing) = error.downcast_ref::<MissingRecordingApis>() {
        return missing.to_string();
    }
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

fn discover_recorded_apis(target_root: &Path, case_source: &Path) -> Result<Vec<String>> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    discover_recorded_apis_from_config(&config, case_source)
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
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings")
        .join(run_id)
}

pub(super) fn comparison_run(target_root: &Path, run_id: &str) -> PathBuf {
    target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("comparison-recordings")
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
}

#[derive(Debug, Deserialize)]
struct StandardCaseRequest {
    method: String,
    uri: String,
    #[serde(default)]
    api_pattern: Option<String>,
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
    fn replacement_recording_must_preserve_the_previous_api_inventory() {
        let required = vec!["GET /common".to_string(), "GET /rare-case".to_string()];

        let error =
            ensure_required_apis_preserved(&required, &["GET /common".to_string()]).unwrap_err();

        assert!(error.to_string().contains("GET /rare-case"));
        assert_eq!(
            recording_rejection(&error),
            "replacement recording lost previously published APIs: GET /rare-case"
        );
        ensure_required_apis_preserved(&required, &required).unwrap();
    }

    #[test]
    fn missing_api_rejection_is_bounded_and_does_not_publish_untyped_errors() {
        let required = (0..20)
            .map(|index| format!("GET /api-{index}"))
            .collect::<Vec<_>>();
        let error = ensure_required_apis_preserved(&required, &[]).unwrap_err();
        let message = recording_rejection(&error.context("private recording path"));
        assert!(message.contains("GET /api-15"));
        assert!(message.ends_with("(and 4 more)"));
        assert!(!message.contains("GET /api-16"));
        assert!(!message.contains("private recording path"));
        let untyped =
            anyhow::anyhow!("replacement recording lost previously published APIs: private path");
        assert_eq!(
            recording_rejection(&untyped),
            "standard recording evidence is unreadable or invalid"
        );
    }

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

        validate_standard_recording_with_process_outputs(target.path(), &state, &[]).unwrap();

        let comparison_output = crate::process_output::ProcessOutputConfig::profile_by_type(
            "metrics-profile".to_string(),
            PathBuf::from("/data1/weibo/logs/profile.log"),
        );
        validate_standard_recording_with_process_outputs(
            target.path(),
            &state,
            &[comparison_output],
        )
        .unwrap();
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
}
