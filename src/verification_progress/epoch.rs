use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{ProgressBaseline, ProgressReport, VerificationStage};
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
        return synchronize_progress(target_root);
    }

    synchronize_progress(target_root)?;
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
    )?;
    synchronize_progress(target_root)
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

fn synchronize_progress(target_root: &Path) -> Result<()> {
    let traffic_e2e_root = target_root.join(crate::repository::TRAFFIC_E2E_ROOT);
    for (file_name, stage) in [
        ("replay-progress.yaml", VerificationStage::Replay),
        ("comparison-progress.yaml", VerificationStage::Comparison),
    ] {
        super::synchronize(&traffic_e2e_root.join(file_name), stage)?;
    }
    Ok(())
}

pub(super) fn merge_archived_baseline(
    progress_path: &Path,
    stage: VerificationStage,
    report: &mut ProgressReport,
) -> Result<Option<bool>> {
    let Some(baseline) = archived_baseline(progress_path, stage)? else {
        return Ok(None);
    };
    if let Some(existing) = &report.observation_baseline {
        ensure!(
            existing == &baseline,
            "{} contains a progress baseline that conflicts with its epoch archive",
            progress_path.display()
        );
        return Ok(Some(false));
    }

    ensure!(
        report.counted_observations.len() as u64 == report.totals.runs.executed,
        "{} cannot attach its epoch baseline because current observations do not reach the current aggregate",
        progress_path.display()
    );
    report.validate_observation_ledger()?;
    for counted in report.counted_observations.values_mut() {
        counted.number = baseline
            .number
            .checked_add(counted.number)
            .context("progress run number overflow while attaching epoch baseline")?;
    }
    report.observation_baseline = Some(baseline);
    report.rebuild_aggregates()?;
    Ok(Some(true))
}

fn archived_baseline(
    progress_path: &Path,
    stage: VerificationStage,
) -> Result<Option<ProgressBaseline>> {
    let traffic_e2e_root = progress_path.parent().with_context(|| {
        format!(
            "progress path {} has no .traffic-e2e directory",
            progress_path.display()
        )
    })?;
    let progress_root = traffic_e2e_root
        .join(crate::repository::LOCAL_ARTIFACTS_RELATIVE_ROOT)
        .join("progress");
    let Some(current) = read_current_epoch(&progress_root.join(CURRENT_EPOCH_FILE))? else {
        return Ok(None);
    };
    let history_root = progress_root
        .join("history")
        .join(format!("before-{}", current.recording_run_id));
    let Some(boundary) = read_yaml::<EpochBoundary>(&history_root.join("boundary.yaml"))? else {
        return Ok(None);
    };
    ensure!(
        boundary.next_recording_run_id == current.recording_run_id,
        "progress epoch archive {} does not belong to the current recording",
        history_root.display()
    );
    let file_name = match stage {
        VerificationStage::Replay => "replay-progress.yaml",
        VerificationStage::Comparison => "comparison-progress.yaml",
    };
    let Some(archived) = read_yaml::<ProgressReport>(&history_root.join(file_name))? else {
        return Ok(None);
    };
    ensure!(
        (super::MIN_SUPPORTED_PROGRESS_VERSION..=super::PROGRESS_VERSION)
            .contains(&archived.version),
        "unsupported archived {:?} progress version {}",
        archived.stage,
        archived.version
    );
    ensure!(
        archived.stage == stage,
        "{} contains {:?} progress, expected {:?}",
        history_root.join(file_name).display(),
        archived.stage,
        stage
    );
    Ok(Some(archived.current_baseline()))
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
    fn new_recording_archives_progress_and_carries_an_idempotent_aggregate_baseline() {
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
        append_observation(
            &replay_path,
            VerificationStage::Replay,
            "legacy-replay",
            "GET /legacy",
            4,
        );
        append_observation(
            &comparison_path,
            VerificationStage::Comparison,
            "legacy-comparison",
            "GET /legacy",
            4,
        );
        super::super::write_payload(
            &replay_path,
            &super::super::yaml_payload(&ProgressReport::new(VerificationStage::Replay)).unwrap(),
        )
        .unwrap();

        begin(target.path(), "20260814075248").unwrap();

        let replay = load(&replay_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert_eq!(replay.totals.runs.executed, 1);
        assert_eq!(replay.totals.cases.executed, 4);
        assert_eq!(replay.observation_baseline.as_ref().unwrap().number, 1);
        assert!(replay.counted_runs.is_empty());
        assert!(replay.counted_observations.is_empty());
        let comparison = load(&comparison_path, VerificationStage::Comparison)
            .unwrap()
            .unwrap();
        assert_eq!(comparison.totals.runs.executed, 1);
        assert!(comparison.counted_runs.is_empty());
        let history = target
            .path()
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("progress/history/before-20260814075248");
        assert_eq!(
            read_yaml::<ProgressReport>(&history.join("replay-progress.yaml"))
                .unwrap()
                .unwrap()
                .totals
                .runs
                .executed,
            1
        );
        assert!(
            fs::read_to_string(history.join("replay-counted-runs.yaml"))
                .unwrap()
                .contains("legacy-replay")
        );

        append_observation(
            &replay_path,
            VerificationStage::Replay,
            "current-replay",
            "GET /legacy",
            6,
        );
        begin(target.path(), "20260814075248").unwrap();
        let replay = load(&replay_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert_eq!(replay.totals.runs.executed, 2);
        assert_eq!(replay.totals.cases.executed, 10);
        assert_eq!(replay.apis["GET /legacy"].success_streak.runs, 2);
        assert!(!replay.counted_runs.contains_key("legacy-replay"));
        assert!(replay.counted_runs.contains_key("current-replay"));
        assert_eq!(replay.counted_observations["current-replay"].number, 2);

        begin(target.path(), "20260815000000").unwrap();
        let replay = load(&replay_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert_eq!(replay.totals.runs.executed, 2);
        assert_eq!(replay.observation_baseline.as_ref().unwrap().number, 2);
        assert!(replay.counted_runs.is_empty());
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

    #[test]
    fn migrates_a_zero_baseline_epoch_without_losing_absent_apis_or_streaks() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join(crate::repository::TRAFFIC_E2E_ROOT)).unwrap();
        let replay_path = target
            .path()
            .join(crate::repository::TRAFFIC_E2E_ROOT)
            .join("replay-progress.yaml");
        append_observation(
            &replay_path,
            VerificationStage::Replay,
            "legacy-a",
            "GET /a",
            4,
        );
        append_observation(
            &replay_path,
            VerificationStage::Replay,
            "legacy-c",
            "POST /c",
            1,
        );
        begin(target.path(), "20260814153355").unwrap();

        let mut current_only = ProgressReport::new(VerificationStage::Replay);
        apply_observation(&mut current_only, "current-a", "GET /a", 10);
        apply_observation(&mut current_only, "current-b", "POST /b", 100);
        super::super::write(&replay_path, &current_only).unwrap();

        let migrated = load(&replay_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert!(migrated.requires_persistence());
        assert_eq!(migrated.totals.runs.executed, 4);
        assert_eq!(migrated.totals.cases.executed, 115);
        assert_eq!(migrated.totals.apis.total, 3);
        assert_eq!(migrated.latest_run.as_ref().unwrap().number, 4);
        assert_eq!(migrated.observation_baseline.as_ref().unwrap().number, 2);
        assert_eq!(migrated.counted_observations["current-a"].number, 3);
        assert_eq!(migrated.counted_observations["current-b"].number, 4);
        assert!(!migrated.counted_runs.contains_key("legacy-a"));
        assert!(!migrated.counted_runs.contains_key("legacy-c"));
        assert!(migrated.apis.contains_key("POST /c"));
        assert_eq!(migrated.apis["GET /a"].totals.runs.executed, 2);
        assert_eq!(migrated.apis["GET /a"].totals.cases.executed, 14);
        assert_eq!(migrated.apis["GET /a"].success_streak.runs, 2);
        assert_eq!(migrated.apis["GET /a"].success_streak.cases, 14);
        assert_eq!(migrated.success_streak.runs, 1);
        assert_eq!(migrated.success_streak.cases, 100);

        assert!(super::super::synchronize(&replay_path, VerificationStage::Replay).unwrap());
        let persisted = load(&replay_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert!(!persisted.requires_persistence());
        assert_eq!(persisted.totals.runs.executed, 4);
        assert_eq!(persisted.counted_observations["current-a"].number, 3);
    }

    fn append_observation(path: &Path, stage: VerificationStage, key: &str, api: &str, cases: u64) {
        let mut report = load(path, stage)
            .unwrap()
            .unwrap_or_else(|| ProgressReport::new(stage));
        apply_observation(&mut report, key, api, cases);
        super::super::write(path, &report).unwrap();
    }

    fn apply_observation(report: &mut ProgressReport, key: &str, api: &str, cases: u64) {
        report
            .apply(ProgressObservation {
                key: key.to_string(),
                evidence_fingerprint: format!("fingerprint-{key}"),
                finished_at: "2026-08-14T00:00:00Z".to_string(),
                apis: BTreeMap::from([(
                    api.to_string(),
                    ApiObservation {
                        cases: LatestCounts {
                            executed: cases,
                            passed: cases,
                        },
                        passed: true,
                    },
                )]),
            })
            .unwrap();
    }
}
