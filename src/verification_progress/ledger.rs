use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    CountedObservation, MAX_COUNTED_RUNS, ProgressBaseline, ProgressReport, VerificationStage,
};
use crate::config::edit::{create_atomic, write_atomic};

const LEDGER_VERSION: u8 = 3;
const MIN_SUPPORTED_LEDGER_VERSION: u8 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CountedRunsLedger {
    version: u8,
    stage: VerificationStage,
    counted_runs: BTreeMap<String, String>,
    #[serde(default)]
    counted_observations: BTreeMap<String, CountedObservation>,
    #[serde(default)]
    observation_baseline: Option<ProgressBaseline>,
}

#[derive(Serialize)]
struct CountedRunsLedgerRef<'a> {
    version: u8,
    stage: VerificationStage,
    counted_runs: &'a BTreeMap<String, String>,
    counted_observations: &'a BTreeMap<String, CountedObservation>,
    observation_baseline: &'a Option<ProgressBaseline>,
}

pub(super) struct LoadedLedger {
    pub(super) exists: bool,
    pub(super) counted_runs: BTreeMap<String, String>,
    pub(super) counted_observations: BTreeMap<String, CountedObservation>,
    pub(super) observation_baseline: Option<ProgressBaseline>,
}

#[derive(Serialize)]
struct ProgressReportWithLedger<'a> {
    version: u8,
    stage: VerificationStage,
    updated_at: &'a str,
    totals: &'a super::ProgressTotals,
    success_streak: &'a super::SuccessStreak,
    latest_run: &'a Option<super::LatestRun>,
    counted_runs: &'a BTreeMap<String, String>,
    counted_observations: &'a BTreeMap<String, CountedObservation>,
    observation_baseline: &'a Option<ProgressBaseline>,
    apis: &'a BTreeMap<String, super::ProgressApi>,
}

pub(super) fn recovery_payload(report: &ProgressReport) -> Result<Vec<u8>> {
    super::yaml_payload(&ProgressReportWithLedger {
        version: report.version,
        stage: report.stage,
        updated_at: &report.updated_at,
        totals: &report.totals,
        success_streak: &report.success_streak,
        latest_run: &report.latest_run,
        counted_runs: &report.counted_runs,
        counted_observations: &report.counted_observations,
        observation_baseline: &report.observation_baseline,
        apis: &report.apis,
    })
}

pub(super) fn load(progress_path: &Path, stage: VerificationStage) -> Result<LoadedLedger> {
    let path = path(progress_path, stage)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LoadedLedger {
                exists: false,
                counted_runs: BTreeMap::new(),
                counted_observations: BTreeMap::new(),
                observation_baseline: None,
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect progress ledger {}", path.display()));
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "progress ledger must be a regular file and not a symlink: {}",
        path.display()
    );
    let payload = fs::read(&path)
        .with_context(|| format!("failed to read progress ledger {}", path.display()))?;
    let ledger: CountedRunsLedger = serde_yaml::from_slice(&payload)
        .with_context(|| format!("failed to parse progress ledger {}", path.display()))?;
    ensure!(
        (MIN_SUPPORTED_LEDGER_VERSION..=LEDGER_VERSION).contains(&ledger.version),
        "unsupported progress ledger version {} in {}",
        ledger.version,
        path.display()
    );
    ensure!(
        ledger.stage == stage,
        "{} contains {:?} progress ledger, expected {:?}",
        path.display(),
        ledger.stage,
        stage
    );
    ensure!(
        ledger.counted_runs.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted runs",
        path.display()
    );
    ensure!(
        ledger.counted_observations.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted observations",
        path.display()
    );
    Ok(LoadedLedger {
        exists: true,
        counted_runs: ledger.counted_runs,
        counted_observations: ledger.counted_observations,
        observation_baseline: ledger.observation_baseline,
    })
}

pub(super) fn write(progress_path: &Path, report: &ProgressReport) -> Result<()> {
    ensure!(
        report.counted_runs.len() <= MAX_COUNTED_RUNS,
        "progress counted-run limit of {MAX_COUNTED_RUNS} was reached"
    );
    ensure!(
        report.counted_observations.len() <= MAX_COUNTED_RUNS,
        "progress counted-observation limit of {MAX_COUNTED_RUNS} was reached"
    );
    let path = path(progress_path, report.stage)?;
    let ledger = CountedRunsLedgerRef {
        version: LEDGER_VERSION,
        stage: report.stage,
        counted_runs: &report.counted_runs,
        counted_observations: &report.counted_observations,
        observation_baseline: &report.observation_baseline,
    };
    let mut payload = serde_yaml::to_string(&ledger)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress ledger must be a regular file and not a symlink: {}",
                path.display()
            );
            write_atomic(&path, &payload)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_atomic(&path, &payload)
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect progress ledger {}", path.display())),
    }
}

pub(super) fn path(progress_path: &Path, stage: VerificationStage) -> Result<PathBuf> {
    let traffic_e2e_dir = progress_path.parent().with_context(|| {
        format!(
            "progress path {} has no .traffic-e2e directory",
            progress_path.display()
        )
    })?;
    let name = match stage {
        VerificationStage::Progress => "counted-runs.yaml",
        VerificationStage::Replay => "replay-counted-runs.yaml",
        VerificationStage::Comparison => "comparison-counted-runs.yaml",
    };
    Ok(traffic_e2e_dir
        .join(crate::repository::LOCAL_ARTIFACTS_RELATIVE_ROOT)
        .join("progress")
        .join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification_progress::{
        ApiObservation, LatestCounts, ProgressObservation, ProgressReport,
    };

    #[test]
    fn stores_counted_runs_below_the_ignored_local_root() {
        let progress_path = Path::new("/target/.traffic-e2e/replay-progress.yaml");

        assert_eq!(
            path(progress_path, VerificationStage::Replay).unwrap(),
            Path::new("/target/.traffic-e2e/local/artifacts/progress/replay-counted-runs.yaml")
        );
    }

    #[test]
    fn failed_ledger_write_leaves_an_embedded_recovery_copy() {
        let directory = tempfile::tempdir().unwrap();
        let progress_path = directory.path().join("replay-progress.yaml");
        let mut report = ProgressReport::new(VerificationStage::Replay);
        let observation = ProgressObservation {
            key: "run-1".to_string(),
            evidence_fingerprint: "evidence-1".to_string(),
            finished_at: "2026-08-03T00:00:00Z".to_string(),
            finalized: true,
            passed: None,
            success_streak: None,
            apis: BTreeMap::from([(
                "GET /users".to_string(),
                ApiObservation {
                    cases: LatestCounts {
                        executed: 1,
                        passed: 1,
                    },
                    finalized: true,
                    passed: true,
                    success_streak: None,
                },
            )]),
        };
        report.apply(observation.clone()).unwrap();
        let ledger_path = path(&progress_path, VerificationStage::Replay).unwrap();
        fs::create_dir_all(&ledger_path).unwrap();

        super::super::write(&progress_path, &report).unwrap_err();

        let recovery = fs::read_to_string(&progress_path).unwrap();
        assert!(recovery.contains("counted_runs:"));
        fs::remove_dir(&ledger_path).unwrap();
        let mut loaded = super::super::load(&progress_path, VerificationStage::Replay)
            .unwrap()
            .unwrap();
        assert!(!loaded.apply(observation).unwrap());
        assert_eq!(loaded.totals.runs.executed, 1);
    }
}
