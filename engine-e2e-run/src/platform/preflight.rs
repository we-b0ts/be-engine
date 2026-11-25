use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::PreflightProbeKind;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CASE_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_RUN_ENTRIES: usize = 20_000;

#[derive(Debug, Clone)]
pub struct ManagedRecordingPreflightOptions {
    pub target_root: PathBuf,
    pub duration_seconds: NonZeroU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingPreflightResult {
    pub status: &'static str,
    pub target_image: ManagedTargetImagePreflightResult,
    pub recording: ManagedRecordingPreflightRecordingResult,
    pub replay_network: super::ManagedReplayNetworkPreflightResult,
    pub target_runtime: super::ManagedTargetRuntimePreflightResult,
    pub managed_by: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedTargetImagePreflightResult {
    pub status: &'static str,
    pub image: crate::TargetImage,
    pub checks: ManagedTargetImagePreflightChecks,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedTargetImagePreflightChecks {
    pub build_contract: bool,
    pub image_contract: bool,
    pub startup_snapshot_contract: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingPreflightRecordingResult {
    pub status: &'static str,
    pub run_id: String,
    pub target_root: PathBuf,
    pub source_snapshot_id: String,
    pub probe_kind: PreflightProbeKind,
    pub manifest: PathBuf,
    pub published_cases: usize,
    pub https_interception_verified: bool,
    pub global_probe_dependency_verified: bool,
}

#[derive(Debug, Deserialize)]
struct RecordingManifest {
    status: String,
    published_cases: usize,
    failed_cases: usize,
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PreflightEvidence {
    pub published_cases: usize,
    pub https_interception_verified: bool,
    pub global_probe_dependency_verified: bool,
    pub probe_kind: PreflightProbeKind,
}

#[derive(Debug, Deserialize)]
struct DependencyEventProbe {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    scheme: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    authority: Option<String>,
    #[serde(default)]
    response_status: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    capture: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CaseDescriptorProbe {
    kind: String,
    source_binding: Option<CaseSourceBindingProbe>,
}

#[derive(Debug, Deserialize)]
struct CaseSourceBindingProbe {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    method: String,
    path_pattern: Option<String>,
}

pub(super) fn validate(manifest_path: &Path, readiness_path: &str) -> Result<PreflightEvidence> {
    let manifest_metadata = regular_file_metadata(manifest_path, "preflight manifest")?;
    ensure!(
        manifest_metadata.len() <= MAX_MANIFEST_BYTES,
        "preflight manifest exceeds the {} byte limit: {}",
        MAX_MANIFEST_BYTES,
        manifest_path.display()
    );
    let manifest: RecordingManifest =
        serde_json::from_slice(&fs::read(manifest_path).with_context(|| {
            format!(
                "failed to read preflight manifest {}",
                manifest_path.display()
            )
        })?)
        .with_context(|| {
            format!(
                "failed to parse preflight manifest {}",
                manifest_path.display()
            )
        })?;
    ensure!(
        manifest.status == "completed",
        "preflight recording did not complete"
    );
    ensure!(
        manifest.failed_cases == 0 && manifest.errors.is_empty(),
        "preflight recording contains failed cases or errors"
    );
    ensure!(
        manifest.published_cases == 1,
        "preflight recording must publish exactly one readiness case; found {}",
        manifest.published_cases
    );

    let run_dir = manifest_path
        .parent()
        .context("preflight manifest has no recording run directory")?;
    let observation = inspect_run(run_dir)?;
    ensure!(
        observation.responses >= manifest.published_cases,
        "preflight recording is missing finalized source responses"
    );
    ensure!(
        observation.readiness_cases == 1
            && observation.readiness_path.as_deref() == Some(readiness_path),
        "preflight recording did not publish exactly one GET readiness case for {readiness_path:?}"
    );
    let (probe_count, probe_kind) =
        count_global_probe_dependencies(&run_dir.join("global-dependencies.jsonl"))?;
    ensure!(
        probe_count == 1,
        "preflight recording must publish exactly one successful {} probe as a Global dependency; found {probe_count}",
        crate::network_probe::POSITIVE_AUTHORITY
    );
    let probe_kind = probe_kind
        .context("preflight recording probe is missing its system-selected runtime attribution")?;
    Ok(PreflightEvidence {
        published_cases: manifest.published_cases,
        https_interception_verified: true,
        global_probe_dependency_verified: true,
        probe_kind,
    })
}

fn count_global_probe_dependencies(path: &Path) -> Result<(usize, Option<PreflightProbeKind>)> {
    let bytes = crate::dependency_index::scoped::read_bytes(path)?;
    let events =
        serde_json::Deserializer::from_reader(bytes.as_slice()).into_iter::<DependencyEventProbe>();
    let mut matches = 0_usize;
    let mut probe_kind = None;
    for event in events {
        let event = event.with_context(|| {
            format!(
                "failed to stream preflight HTTP evidence {}",
                path.display()
            )
        })?;
        let has_response_status = event
            .response_status
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| (100..=599).contains(&status));
        let event_probe_kind = match event.capture["attribution"]["initialization_unit"].as_str() {
            Some("preflight_probe/java_truststore") => Some(PreflightProbeKind::JavaTruststore),
            Some("preflight_probe/system_network") => Some(PreflightProbeKind::SystemNetwork),
            _ => None,
        };
        if event.event_type == "http_exchange"
            && matches!(event.scheme.as_str(), "https" | "fake_ip_https")
            && event.method == "GET"
            && crate::network_probe::matches_positive_endpoint(
                event.authority.as_deref(),
                &event.uri,
            )
            && has_response_status
            && event.error.is_none()
            && event.capture["attribution"]["kind"] == "startup"
        {
            matches += 1;
            probe_kind = event_probe_kind;
        }
    }
    Ok((matches, probe_kind))
}

#[derive(Debug, Default)]
struct RunObservation {
    responses: usize,
    readiness_cases: usize,
    readiness_path: Option<String>,
}

fn inspect_run(run_dir: &Path) -> Result<RunObservation> {
    let metadata = fs::symlink_metadata(run_dir)
        .with_context(|| format!("failed to inspect preflight run {}", run_dir.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "preflight run is not a regular directory: {}",
        run_dir.display()
    );
    let mut pending = vec![run_dir.to_path_buf()];
    let mut entries = 0_usize;
    let mut observation = RunObservation::default();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).with_context(|| {
            format!("failed to read preflight directory {}", directory.display())
        })? {
            let path = entry
                .with_context(|| format!("failed to read an entry below {}", directory.display()))?
                .path();
            entries += 1;
            ensure!(
                entries <= MAX_RUN_ENTRIES,
                "preflight run exceeds the {} entry limit",
                MAX_RUN_ENTRIES
            );
            let metadata = fs::symlink_metadata(&path).with_context(|| {
                format!("failed to inspect preflight artifact {}", path.display())
            })?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "preflight artifact must not be a symlink: {}",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            ensure!(
                metadata.is_file(),
                "preflight artifact must be a regular file: {}",
                path.display()
            );
            match path.file_name().and_then(|name| name.to_str()) {
                Some("expected-response.json") | Some("expected_response.json") => {
                    observation.responses += 1;
                }
                Some("case.json") => {
                    ensure!(
                        metadata.len() <= MAX_CASE_DESCRIPTOR_BYTES,
                        "preflight case descriptor exceeds the {} byte limit: {}",
                        MAX_CASE_DESCRIPTOR_BYTES,
                        path.display()
                    );
                    let descriptor: CaseDescriptorProbe =
                        serde_json::from_slice(&fs::read(&path).with_context(|| {
                            format!(
                                "failed to read preflight case descriptor {}",
                                path.display()
                            )
                        })?)
                        .with_context(|| {
                            format!(
                                "failed to parse preflight case descriptor {}",
                                path.display()
                            )
                        })?;
                    match descriptor.kind.as_str() {
                        "http"
                            if descriptor.source_binding.as_ref().is_some_and(|binding| {
                                binding.protocol == "http" && binding.method == "GET"
                            }) =>
                        {
                            observation.readiness_cases += 1;
                            observation.readiness_path = descriptor
                                .source_binding
                                .and_then(|binding| binding.path_pattern);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(observation)
}

fn regular_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} is not a regular file: {}",
        path.display()
    );
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_image_preflight_reports_only_static_checks() {
        let result = ManagedTargetImagePreflightResult {
            status: "passed",
            image: crate::TargetImage {
                tag: "traffic-e2e/example-target:cache".to_string(),
                id: format!("sha256:{}", "a".repeat(64)),
            },
            checks: ManagedTargetImagePreflightChecks {
                build_contract: true,
                image_contract: true,
                startup_snapshot_contract: true,
            },
        };

        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["status"], "passed");
        assert_eq!(value["checks"]["build_contract"], true);
        assert_eq!(value["checks"]["image_contract"], true);
        assert_eq!(value["checks"]["startup_snapshot_contract"], true);
        assert!(value["checks"].get("readiness").is_none());
        assert!(value["checks"].get("process_identity").is_none());
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("recordings/20260805000000");
        let case = run.join("apis/example/case-1");
        fs::create_dir_all(&case).unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
        fs::write(
            case.join("case.json"),
            r#"{"kind":"http","source_binding":{"protocol":"http","method":"GET","path_pattern":"/healthz"}}"#,
        )
        .unwrap();
        let manifest = run.join("recording-run.json");
        fs::write(
            &manifest,
            r#"{"status":"completed","published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        (temp, manifest)
    }

    fn probe_event(matched_by: &str) -> String {
        format!(
            concat!(
                r#"{{"event_type":"http_exchange","scheme":"fake_ip_https","method":"GET","uri":"/","authority":"example.com:443","response_status":302,"error":null,"capture":{{"phase":"runtime","attribution":{{"kind":"startup","initialization_unit":"preflight_probe/{}"}}}}}}"#,
                "\n"
            ),
            matched_by
        )
    }

    #[test]
    fn accepts_exactly_one_java_global_probe_dependency() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("java_truststore"),
        )
        .unwrap();

        assert_eq!(
            validate(&manifest, "/healthz").unwrap(),
            PreflightEvidence {
                published_cases: 1,
                https_interception_verified: true,
                global_probe_dependency_verified: true,
                probe_kind: PreflightProbeKind::JavaTruststore,
            }
        );
    }

    #[test]
    fn accepts_system_selected_network_probe() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();

        assert_eq!(
            validate(&manifest, "/healthz").unwrap().probe_kind,
            PreflightProbeKind::SystemNetwork
        );
    }

    #[test]
    fn rejects_probe_found_only_in_traffic_jsonl() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(run.join("traffic.jsonl"), probe_event("java_truststore")).unwrap();

        let error = format!("{:#}", validate(&manifest, "/healthz").unwrap_err());
        assert!(
            error.contains("No such file") || error.contains("preflight HTTP evidence"),
            "{error}"
        );
    }

    #[test]
    fn rejects_unknown_probe_attribution_or_duplicates() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("declared_language"),
        )
        .unwrap();
        let error = validate(&manifest, "/healthz").unwrap_err().to_string();
        assert!(error.contains("system-selected runtime attribution"));

        fs::write(
            run.join("global-dependencies.jsonl"),
            format!(
                "{}{}",
                probe_event("java_truststore"),
                probe_event("java_truststore")
            ),
        )
        .unwrap();

        let error = validate(&manifest, "/healthz").unwrap_err().to_string();
        assert!(error.contains("found 2"));
    }

    #[test]
    fn preflight_rejects_a_window_without_one_readiness_case() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::remove_dir_all(run.join("apis")).unwrap();
        fs::write(
            &manifest,
            r#"{"status":"completed","published_cases":0,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();

        let error = validate(&manifest, "/healthz").unwrap_err().to_string();
        assert!(error.contains("exactly one readiness case"));
    }
}
