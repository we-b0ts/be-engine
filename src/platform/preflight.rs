use std::fs::{self, File};
use std::io::BufReader;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{PreflightProbeKind, RecordingApi};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CASE_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_TRAFFIC_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RUN_ENTRIES: usize = 20_000;
const MAX_MOTAN_FAILURES: usize = 16;
const MAX_MOTAN_FAILURE_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct ManagedRecordingPreflightOptions {
    pub target_root: PathBuf,
    pub duration_seconds: NonZeroU64,
    pub breeze_no_fallback: bool,
    pub apis: Vec<RecordingApi>,
    pub per_api_case_limit: Option<NonZeroUsize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingPreflightResult {
    pub status: &'static str,
    pub target_container: crate::TargetContainerPreflightResult,
    pub recording: ManagedRecordingPreflightRecordingResult,
    pub replay_network: super::ManagedReplayNetworkPreflightResult,
    pub managed_by: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingPreflightRecordingResult {
    pub status: &'static str,
    pub run_id: String,
    pub target_root: PathBuf,
    pub source_container: String,
    pub probe_kind: PreflightProbeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_container: Option<String>,
    pub manifest: PathBuf,
    pub published_cases: usize,
    pub https_interception_verified: bool,
    pub global_probe_dependency_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_dns_resolution_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub motan: Option<ManagedMotanPreflightResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedMotanPreflightResult {
    pub status: MotanPreflightStatus,
    pub observed_cases: usize,
    pub source_port: u16,
    pub gateway_port: u16,
    pub validation_deferred: bool,
    pub motan_replay_command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_action: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MotanPreflightStatus {
    Verified,
    NotObserved,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedMotanRecordingResult {
    pub status: MotanPreflightStatus,
    pub observed_cases: usize,
    pub validation_deferred: bool,
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
    pub breeze_dns_resolution_verified: bool,
    pub probe_kind: PreflightProbeKind,
    pub motan_status: Option<MotanPreflightStatus>,
    pub motan_cases: usize,
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
    global_dependency_reason: Option<String>,
    #[serde(default)]
    global_dependency_phase: Option<String>,
    #[serde(default)]
    global_dependency_matched_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CaseDescriptorProbe {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct TrafficEventProbe {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    error: String,
}

pub(super) fn validate(
    manifest_path: &Path,
    motan_enabled: bool,
    breeze_enabled: bool,
) -> Result<PreflightEvidence> {
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
    if !motan_enabled {
        ensure!(
            manifest.published_cases > 0,
            "preflight recording published no cases; send a controlled request through the recording gateway while the command is running"
        );
    }

    let run_dir = manifest_path
        .parent()
        .context("preflight manifest has no recording run directory")?;
    if breeze_enabled {
        validate_breeze_dns_resolution(run_dir)?;
    }
    let observation = inspect_run(run_dir)?;
    ensure!(
        observation.responses >= manifest.published_cases,
        "preflight recording is missing finalized source responses"
    );
    if motan_enabled {
        validate_motan_gateway_observation(run_dir)?;
    }
    let (probe_count, probe_kind) =
        count_global_probe_dependencies(&run_dir.join("global-dependencies.jsonl"))?;
    ensure!(
        probe_count == 1,
        "preflight recording must publish exactly one successful demo.test probe as a Global dependency; found {probe_count}"
    );
    let probe_kind = probe_kind
        .context("preflight recording probe is missing its system-selected runtime attribution")?;
    Ok(PreflightEvidence {
        published_cases: manifest.published_cases,
        https_interception_verified: true,
        global_probe_dependency_verified: true,
        breeze_dns_resolution_verified: breeze_enabled,
        probe_kind,
        motan_status: motan_enabled.then_some(if observation.motan_cases > 0 {
            MotanPreflightStatus::Verified
        } else {
            MotanPreflightStatus::NotObserved
        }),
        motan_cases: observation.motan_cases,
    })
}

fn validate_breeze_dns_resolution(run_dir: &Path) -> Result<()> {
    let network_manifest = crate::recording_network::RecordingNetworkManifest::load(
        &run_dir.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
    )?;
    ensure!(
        network_manifest
            .resolved_domains
            .iter()
            .any(|domain| domain == "breeze.recording"),
        "Breeze preflight did not resolve breeze.recording through Recorder DNS"
    );
    Ok(())
}

pub(super) fn validate_motan_recording(
    manifest_path: &Path,
) -> Result<ManagedMotanRecordingResult> {
    let run_dir = manifest_path
        .parent()
        .context("managed recording manifest has no recording run directory")?;
    let observation = inspect_run(run_dir)?;
    validate_motan_gateway_observation(run_dir)?;
    let status = if observation.motan_cases > 0 {
        MotanPreflightStatus::Verified
    } else {
        MotanPreflightStatus::NotObserved
    };
    Ok(ManagedMotanRecordingResult {
        status,
        observed_cases: observation.motan_cases,
        validation_deferred: status == MotanPreflightStatus::NotObserved,
    })
}

fn validate_motan_gateway_observation(run_dir: &Path) -> Result<()> {
    let failures = motan_gateway_failures(&run_dir.join("traffic.jsonl"))?;
    ensure!(
        failures.is_empty(),
        "Motan traffic reached the recording gateway but failed: {}",
        failures.join("; ")
    );
    Ok(())
}

fn motan_gateway_failures(path: &Path) -> Result<Vec<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect preflight traffic evidence {}",
                    path.display()
                )
            });
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "preflight traffic evidence is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_TRAFFIC_EVIDENCE_BYTES,
        "preflight traffic evidence exceeds the {} byte limit: {}",
        MAX_TRAFFIC_EVIDENCE_BYTES,
        path.display()
    );
    let events = serde_json::Deserializer::from_reader(BufReader::new(File::open(path)?))
        .into_iter::<TrafficEventProbe>();
    let mut failures = Vec::new();
    for event in events {
        let event = event.with_context(|| {
            format!(
                "failed to stream preflight traffic evidence {}",
                path.display()
            )
        })?;
        if event.event_type == "proxy_error" && event.protocol == "motan_gateway" {
            failures.push(bounded_text(event.error, MAX_MOTAN_FAILURE_BYTES));
            if failures.len() == MAX_MOTAN_FAILURES {
                break;
            }
        }
    }
    Ok(failures)
}

fn bounded_text(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let suffix = "… [truncated]";
    let mut end = max_bytes.saturating_sub(suffix.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value.push_str(suffix);
    value
}

fn count_global_probe_dependencies(path: &Path) -> Result<(usize, Option<PreflightProbeKind>)> {
    regular_file_metadata(path, "preflight HTTP evidence")?;
    let file = File::open(path)
        .with_context(|| format!("failed to open preflight HTTP evidence {}", path.display()))?;
    let events = serde_json::Deserializer::from_reader(BufReader::new(file))
        .into_iter::<DependencyEventProbe>();
    let mut matches = 0_usize;
    let mut probe_kind = None;
    for event in events {
        let event = event.with_context(|| {
            format!(
                "failed to stream preflight HTTP evidence {}",
                path.display()
            )
        })?;
        let authority_matches = event.authority.as_deref().is_some_and(|authority| {
            authority
                .strip_suffix(":443")
                .unwrap_or(authority)
                .eq_ignore_ascii_case(crate::network_probe::POSITIVE_AUTHORITY)
        });
        let uri_matches = event.uri == "/"
            || event.uri == crate::network_probe::POSITIVE_URL
            || event.uri == "https://demo.test";
        let has_response_status = event
            .response_status
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| (100..=599).contains(&status));
        let event_probe_kind = match event.global_dependency_matched_by.as_deref() {
            Some("java_truststore") => Some(PreflightProbeKind::JavaTruststore),
            Some("system_network") => Some(PreflightProbeKind::SystemNetwork),
            _ => None,
        };
        if event.event_type == "http_exchange"
            && matches!(event.scheme.as_str(), "https" | "fake_ip_https")
            && event.method == "GET"
            && authority_matches
            && uri_matches
            && has_response_status
            && event.error.is_none()
            && event.global_dependency_reason.as_deref() == Some("preflight_probe")
            && event.global_dependency_phase.as_deref() == Some("runtime")
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
    motan_cases: usize,
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
                    if descriptor.kind == "motan_rpc" {
                        observation.motan_cases += 1;
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

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("recordings/20260805000000");
        let case = run.join("record-api/example/case-1");
        fs::create_dir_all(&case).unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
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
                r#"{{"event_type":"http_exchange","scheme":"fake_ip_https","method":"GET","uri":"/","authority":"demo.test:443","response_status":302,"error":null,"global_dependency_reason":"preflight_probe","global_dependency_phase":"runtime","global_dependency_matched_by":"{}"}}"#,
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
            validate(&manifest, false, false).unwrap(),
            PreflightEvidence {
                published_cases: 1,
                https_interception_verified: true,
                global_probe_dependency_verified: true,
                breeze_dns_resolution_verified: false,
                probe_kind: PreflightProbeKind::JavaTruststore,
                motan_status: None,
                motan_cases: 0,
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
            validate(&manifest, false, false).unwrap().probe_kind,
            PreflightProbeKind::SystemNetwork
        );
    }

    #[test]
    fn rejects_probe_found_only_in_traffic_jsonl() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(run.join("traffic.jsonl"), probe_event("java_truststore")).unwrap();

        let error = validate(&manifest, false, false).unwrap_err().to_string();
        assert!(error.contains("global-dependencies.jsonl"));
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
        let error = validate(&manifest, false, false).unwrap_err().to_string();
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

        let error = validate(&manifest, false, false).unwrap_err().to_string();
        assert!(error.contains("found 2"));
    }

    #[test]
    fn motan_preflight_defers_when_no_motan_case_is_observed() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();

        let evidence = validate(&manifest, true, false).unwrap();
        assert_eq!(
            evidence.motan_status,
            Some(MotanPreflightStatus::NotObserved)
        );
        assert_eq!(evidence.motan_cases, 0);
        let recording = validate_motan_recording(&manifest).unwrap();
        assert_eq!(recording.status, MotanPreflightStatus::NotObserved);
        assert!(recording.validation_deferred);
    }

    #[test]
    fn motan_preflight_allows_a_window_with_no_business_cases() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::remove_dir_all(run.join("record-api")).unwrap();
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

        let evidence = validate(&manifest, true, false).unwrap();
        assert_eq!(evidence.published_cases, 0);
        assert_eq!(
            evidence.motan_status,
            Some(MotanPreflightStatus::NotObserved)
        );
    }

    #[test]
    fn motan_preflight_verifies_a_published_motan_case() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        let case = run.join("record-api/example/case-1");
        fs::write(case.join("case.json"), r#"{"kind":"motan_rpc"}"#).unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();

        let evidence = validate(&manifest, true, false).unwrap();
        assert_eq!(evidence.motan_status, Some(MotanPreflightStatus::Verified));
        assert_eq!(evidence.motan_cases, 1);
        let recording = validate_motan_recording(&manifest).unwrap();
        assert_eq!(recording.status, MotanPreflightStatus::Verified);
        assert!(!recording.validation_deferred);
    }

    #[test]
    fn motan_preflight_rejects_observed_gateway_failures() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();
        fs::write(
            run.join("traffic.jsonl"),
            r#"{"event_type":"proxy_error","protocol":"motan_gateway","error":"bad frame"}
"#,
        )
        .unwrap();

        let error = validate(&manifest, true, false).unwrap_err().to_string();
        assert!(error.contains("Motan traffic reached"));
        assert!(error.contains("bad frame"));
        assert!(validate_motan_recording(&manifest).is_err());
    }

    #[test]
    fn breeze_preflight_requires_recorder_observed_dns_resolution() {
        let (_temp, manifest) = fixture();
        let run = manifest.parent().unwrap();
        fs::write(
            run.join("global-dependencies.jsonl"),
            probe_event("system_network"),
        )
        .unwrap();
        fs::write(
            run.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
            r#"{"version":1,"resolved_domains":["breeze.recording"],"accessed_endpoints":[]}"#,
        )
        .unwrap();

        let evidence = validate(&manifest, false, true).unwrap();
        assert!(evidence.breeze_dns_resolution_verified);

        fs::write(
            run.join(crate::recording_network::RECORDING_NETWORK_FILENAME),
            r#"{"version":1,"resolved_domains":[],"accessed_endpoints":[]}"#,
        )
        .unwrap();
        let error = validate(&manifest, false, true).unwrap_err().to_string();
        assert!(error.contains("did not resolve breeze.recording through Recorder DNS"));
    }
}
