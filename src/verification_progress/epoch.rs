use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{ProgressReport, VerificationStage};
use crate::config::edit::{create_atomic, write_atomic};

const EPOCH_VERSION: u8 = 1;
const CURRENT_EPOCH_FILE: &str = "current-epoch.yaml";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentEpoch {
    version: u8,
    recording_run_id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochBoundary {
    version: u8,
    previous_recording_run_id: Option<String>,
    next_recording_run_id: String,
}

pub(crate) fn begin(target_root: &Path, recording_run_id: &str) -> Result<()> {
    validate_recording_run_id(recording_run_id)?;
    let progress_root = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(crate::repository::LOCAL_ARTIFACTS_RELATIVE_ROOT)
        .join("progress");
    let current_path = progress_root.join(CURRENT_EPOCH_FILE);
    let current = read_current_epoch(&current_path)?;
    if current
        .as_ref()
        .is_some_and(|epoch| epoch.recording_run_id == recording_run_id)
    {
        return Ok(());
    }

    archive_current_progress(
        target_root,
        &progress_root,
        current.as_ref(),
        recording_run_id,
    )?;
    reset_progress(target_root)?;
    write_yaml(
        &current_path,
        &CurrentEpoch {
            version: EPOCH_VERSION,
            recording_run_id: recording_run_id.to_string(),
        },
    )
}

fn archive_current_progress(
    target_root: &Path,
    progress_root: &Path,
    current: Option<&CurrentEpoch>,
    next_recording_run_id: &str,
) -> Result<()> {
    let history_root = progress_root
        .join("history")
        .join(format!("before-{next_recording_run_id}"));
    let boundary_path = history_root.join("boundary.yaml");
    let boundary = EpochBoundary {
        version: EPOCH_VERSION,
        previous_recording_run_id: current.map(|epoch| epoch.recording_run_id.clone()),
        next_recording_run_id: next_recording_run_id.to_string(),
    };
    if let Some(existing) = read_yaml::<EpochBoundary>(&boundary_path)? {
        ensure!(
            existing == boundary,
            "progress epoch boundary {} belongs to a different transition",
            boundary_path.display()
        );
        return Ok(());
    }

    let traffic_e2e_root = target_root.join(crate::repository::TRAFFIC_E2E_ROOT);
    let replay_path = traffic_e2e_root.join("replay-progress.yaml");
    let comparison_path = traffic_e2e_root.join("comparison-progress.yaml");
    let archive_sources = [
        (
            replay_path.clone(),
            history_root.join("replay-progress.yaml"),
        ),
        (
            super::ledger::path(&replay_path, VerificationStage::Replay)?,
            history_root.join("replay-counted-runs.yaml"),
        ),
        (
            comparison_path.clone(),
            history_root.join("comparison-progress.yaml"),
        ),
        (
            super::ledger::path(&comparison_path, VerificationStage::Comparison)?,
            history_root.join("comparison-counted-runs.yaml"),
        ),
        (
            progress_root.join(CURRENT_EPOCH_FILE),
            history_root.join("previous-epoch.yaml"),
        ),
    ];
    for (source, destination) in archive_sources {
        archive_file(&source, &destination)?;
    }
    write_yaml(&boundary_path, &boundary)
}

fn archive_file(source: &Path, destination: &Path) -> Result<()> {
    let source_metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect progress {}", source.display()));
        }
    };
    ensure!(
        source_metadata.is_file() && !source_metadata.file_type().is_symlink(),
        "progress epoch source must be a regular file and not a symlink: {}",
        source.display()
    );
    let payload = fs::read(source)
        .with_context(|| format!("failed to read progress epoch source {}", source.display()))?;

    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress epoch archive must be a regular file and not a symlink: {}",
                destination.display()
            );
            let archived = fs::read(destination).with_context(|| {
                format!(
                    "failed to read progress epoch archive {}",
                    destination.display()
                )
            })?;
            ensure!(
                archived == payload,
                "progress epoch archive {} conflicts with its source",
                destination.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_atomic(destination, &payload)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect progress epoch archive {}",
                destination.display()
            )
        }),
    }
}

fn reset_progress(target_root: &Path) -> Result<()> {
    let traffic_e2e_root = target_root.join(crate::repository::TRAFFIC_E2E_ROOT);
    for (file_name, stage) in [
        ("replay-progress.yaml", VerificationStage::Replay),
        ("comparison-progress.yaml", VerificationStage::Comparison),
    ] {
        super::write(
            &traffic_e2e_root.join(file_name),
            &ProgressReport::new(stage),
        )?;
    }
    Ok(())
}

fn read_current_epoch(path: &Path) -> Result<Option<CurrentEpoch>> {
    let epoch = read_yaml::<CurrentEpoch>(path)?;
    if let Some(epoch) = &epoch {
        ensure!(
            epoch.version == EPOCH_VERSION,
            "unsupported progress epoch version {} in {}",
            epoch.version,
            path.display()
        );
        validate_recording_run_id(&epoch.recording_run_id)?;
    }
    Ok(epoch)
}

fn read_yaml<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect progress epoch {}", path.display()));
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "progress epoch data must be a regular file and not a symlink: {}",
        path.display()
    );
    let payload = fs::read(path)
        .with_context(|| format!("failed to read progress epoch {}", path.display()))?;
    serde_yaml::from_slice(&payload)
        .with_context(|| format!("failed to parse progress epoch {}", path.display()))
        .map(Some)
}

fn write_yaml(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut payload = serde_yaml::to_string(value)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress epoch data must be a regular file and not a symlink: {}",
                path.display()
            );
            write_atomic(path, &payload)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_atomic(path, &payload),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect progress epoch {}", path.display())),
    }
}

fn validate_recording_run_id(run_id: &str) -> Result<()> {
    ensure!(
        run_id.len() == 14 && run_id.bytes().all(|byte| byte.is_ascii_digit()),
        "progress epoch requires a 14-digit recording run ID"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::verification_progress::{ApiObservation, LatestCounts, ProgressObservation, load};

    #[test]
    fn new_recording_archives_mismatched_progress_and_starts_an_idempotent_epoch() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join(crate::repository::TRAFFIC_E2E_ROOT)).unwrap();
        let replay_path = target
            .path()
            .join(crate::repository::TRAFFIC_E2E_ROOT)
            .join("replay-progress.yaml");
        let comparison_path = target
            .path()
            .join(crate::repository::TRAFFIC_E2E_ROOT)
            .join("comparison-progress.yaml");
        write_observation(&replay_path, VerificationStage::Replay, "legacy-replay");
        write_observation(
            &comparison_path,
            VerificationStage::Comparison,
            "legacy-comparison",
        );
        super::super::write_payload(
            &replay_path,
            &super::super::yaml_payload(&ProgressReport::new(VerificationStage::Replay)).unwrap(),
        )
        .unwrap();
        let legacy_replay = fs::read(&replay_path).unwrap();
        let legacy_replay_ledger =
            fs::read(super::super::ledger::path(&replay_path, VerificationStage::Replay).unwrap())
                .unwrap();

        begin(target.path(), "20260814075248").unwrap();

        assert_empty(&replay_path, VerificationStage::Replay);
        assert_empty(&comparison_path, VerificationStage::Comparison);
        let history = target
            .path()
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("progress/history/before-20260814075248");
        assert_eq!(
            fs::read(history.join("replay-progress.yaml")).unwrap(),
            legacy_replay
        );
        assert_eq!(
            fs::read(history.join("replay-counted-runs.yaml")).unwrap(),
            legacy_replay_ledger
        );

        write_observation(&replay_path, VerificationStage::Replay, "current-replay");
        begin(target.path(), "20260814075248").unwrap();
        assert_eq!(
            load(&replay_path, VerificationStage::Replay)
                .unwrap()
                .unwrap()
                .totals
                .runs
                .executed,
            1
        );

        begin(target.path(), "20260815000000").unwrap();
        assert_empty(&replay_path, VerificationStage::Replay);
        let second_history = target
            .path()
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("progress/history/before-20260815000000");
        assert_eq!(
            read_yaml::<CurrentEpoch>(&second_history.join("previous-epoch.yaml"))
                .unwrap()
                .unwrap()
                .recording_run_id,
            "20260814075248"
        );
        assert!(second_history.join("replay-progress.yaml").is_file());
        assert!(second_history.join("replay-counted-runs.yaml").is_file());
    }

    fn write_observation(path: &Path, stage: VerificationStage, key: &str) {
        let mut report = ProgressReport::new(stage);
        report
            .apply(ProgressObservation {
                key: key.to_string(),
                evidence_fingerprint: format!("fingerprint-{key}"),
                finished_at: "2026-08-14T00:00:00Z".to_string(),
                apis: BTreeMap::from([(
                    "GET /api".to_string(),
                    ApiObservation {
                        cases: LatestCounts {
                            executed: 1,
                            passed: 1,
                        },
                        passed: true,
                    },
                )]),
            })
            .unwrap();
        super::super::write(path, &report).unwrap();
    }

    fn assert_empty(path: &Path, stage: VerificationStage) {
        let report = load(path, stage).unwrap().unwrap();
        assert_eq!(report.totals.runs.executed, 0);
        assert!(report.counted_runs.is_empty());
        assert!(report.counted_observations.is_empty());
    }
}
