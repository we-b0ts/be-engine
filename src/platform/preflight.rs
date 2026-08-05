use std::fs::{self, File};
use std::io::BufReader;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::RecordingApi;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RUN_ENTRIES: usize = 20_000;

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
    pub run_id: String,
    pub target_root: PathBuf,
    pub source_container: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_container: Option<String>,
    pub manifest: PathBuf,
    pub published_cases: usize,
    pub https_interception_verified: bool,
    pub managed_by: &'static str,
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
}

#[derive(Debug, Deserialize)]
struct DependencyEventProbe {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    scheme: String,
    #[serde(default)]
    response_status: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

pub(super) fn validate(manifest_path: &Path) -> Result<PreflightEvidence> {
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
        manifest.published_cases > 0,
        "preflight recording published no cases; send a controlled request through the recording gateway while the command is running"
    );

    let run_dir = manifest_path
        .parent()
        .context("preflight manifest has no recording run directory")?;
    let observation = inspect_run(run_dir)?;
    ensure!(
        observation.responses >= manifest.published_cases,
        "preflight recording is missing finalized source responses"
    );
    let mut https_interception_verified = false;
    for path in &observation.http_evidence {
        if has_successful_https_exchange(path)? {
            https_interception_verified = true;
            break;
        }
    }
    ensure!(
        https_interception_verified,
        "preflight recording did not capture a successful HTTPS interception"
    );
    Ok(PreflightEvidence {
        published_cases: manifest.published_cases,
        https_interception_verified: true,
    })
}

fn has_successful_https_exchange(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    regular_file_metadata(path, "preflight HTTP evidence")?;
    let file = File::open(path)
        .with_context(|| format!("failed to open preflight HTTP evidence {}", path.display()))?;
    let events = serde_json::Deserializer::from_reader(BufReader::new(file))
        .into_iter::<DependencyEventProbe>();
    for event in events {
        let event = event.with_context(|| {
            format!(
                "failed to stream preflight HTTP evidence {}",
                path.display()
            )
        })?;
        let is_https = matches!(event.scheme.as_str(), "https" | "fake_ip_https");
        let has_response_status = event
            .response_status
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|status| (100..=599).contains(&status));
        if event.event_type == "http_exchange"
            && is_https
            && has_response_status
            && event.error.is_none()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Default)]
struct RunObservation {
    responses: usize,
    http_evidence: Vec<PathBuf>,
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
                Some("dependencies.jsonl")
                | Some("global-dependencies.jsonl")
                | Some("traffic.jsonl") => {
                    observation.http_evidence.push(path);
                }
                _ => {}
            }
        }
    }
    observation.http_evidence.sort_by_key(|path| {
        match path.file_name().and_then(|name| name.to_str()) {
            Some("dependencies.jsonl") => 0,
            Some("traffic.jsonl") => 1,
            Some("global-dependencies.jsonl") => 2,
            _ => 3,
        }
    });
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
    fn accepts_a_clean_case_and_streamed_https_probe() {
        let temp = tempfile::tempdir().unwrap();
        let run = temp.path().join("recordings/20260805000000");
        let case = run.join("record-api/example/case-1");
        fs::create_dir_all(&case).unwrap();
        fs::write(case.join("expected-response.json"), "{}\n").unwrap();
        fs::write(case.join("dependencies.jsonl"), "").unwrap();
        let manifest = run.join("recording-run.json");
        fs::write(
            &manifest,
            r#"{"status":"completed","published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        fs::write(
            run.join("traffic.jsonl"),
            concat!(
                r#"{"event_type":"http_exchange","scheme":"http","authority":"demo.test","response_status":200,"error":null}"#,
                "\n",
                r#"{"event_type":"http_exchange","scheme":"fake_ip_https","authority":"demo.test:443","response_status":302,"error":null}"#,
                "\n",
                "this trailing content must not be parsed\n"
            ),
        )
        .unwrap();

        assert_eq!(
            validate(&manifest).unwrap(),
            PreflightEvidence {
                published_cases: 1,
                https_interception_verified: true,
            }
        );
    }

    #[test]
    fn accepts_a_successful_https_exchange_from_case_evidence() {
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
        fs::write(
            case.join("dependencies.jsonl"),
            concat!(
                r#"{"event_type":"motan_exchange","response_status":"VALUE u2978698387 4096 72"}"#,
                "\n",
                r#"{"event_type":"http_exchange","scheme":"https","authority":"unrelated.example","response_status":200,"error":null}"#,
                "\n"
            ),
        )
        .unwrap();

        assert!(validate(&manifest).is_ok());
    }

    #[test]
    fn rejects_a_clean_case_without_a_successful_https_exchange() {
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
        fs::write(
            run.join("global-dependencies.jsonl"),
            concat!(
                r#"{"event_type":"http_exchange","scheme":"http","authority":"example.com","response_status":200,"error":null}"#,
                "\n",
                r#"{"event_type":"http_exchange","scheme":"fake_ip_https","authority":"demo.test","response_status":null,"error":"certificate rejected"}"#,
                "\n"
            ),
        )
        .unwrap();

        let error = validate(&manifest).unwrap_err().to_string();
        assert!(error.contains("successful HTTPS interception"));
    }
}
