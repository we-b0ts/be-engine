use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::edit::{create_atomic, write_atomic};

pub(crate) const PROGRESS_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationStage {
    Replay,
    Comparison,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressReport {
    pub(crate) version: u8,
    pub(crate) stage: VerificationStage,
    pub(crate) updated_at: String,
    pub(crate) totals: ProgressTotals,
    pub(crate) success_streak: SuccessStreak,
    pub(crate) latest_run: Option<LatestRun>,
    pub(crate) apis: BTreeMap<String, ProgressApi>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressTotals {
    pub(crate) runs: SuccessCounts,
    pub(crate) cases: SuccessCounts,
    pub(crate) apis: ApiCounts,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessCounts {
    pub(crate) executed: u64,
    pub(crate) passed: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiCounts {
    pub(crate) total: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessStreak {
    pub(crate) runs: u64,
    pub(crate) cases: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestRun {
    pub(crate) key: String,
    pub(crate) evidence_fingerprint: String,
    pub(crate) number: u64,
    pub(crate) passed: bool,
    pub(crate) cases: LatestCounts,
    pub(crate) apis: LatestCounts,
    pub(crate) scope: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestCounts {
    pub(crate) executed: u64,
    #[serde(default, alias = "successful")]
    pub(crate) passed: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressApi {
    pub(crate) totals: ApiTotals,
    pub(crate) success_streak: SuccessStreak,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiTotals {
    pub(crate) runs: SuccessCounts,
    pub(crate) cases: SuccessCounts,
}

#[derive(Debug, Clone)]
pub(crate) struct ProgressObservation {
    pub(crate) key: String,
    pub(crate) evidence_fingerprint: String,
    pub(crate) finished_at: String,
    pub(crate) apis: BTreeMap<String, ApiObservation>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApiObservation {
    pub(crate) cases: LatestCounts,
    pub(crate) passed: bool,
}

impl ProgressReport {
    pub(crate) fn new(stage: VerificationStage) -> Self {
        Self {
            version: PROGRESS_VERSION,
            stage,
            updated_at: String::new(),
            totals: ProgressTotals::default(),
            success_streak: SuccessStreak::default(),
            latest_run: None,
            apis: BTreeMap::new(),
        }
    }

    pub(crate) fn apply(&mut self, observation: ProgressObservation) -> Result<bool> {
        ensure!(
            self.version == PROGRESS_VERSION,
            "unsupported {:?} progress version {}",
            self.stage,
            self.version
        );
        ensure!(
            !observation.key.is_empty(),
            "progress run key must not be empty"
        );
        ensure!(
            !observation.evidence_fingerprint.is_empty(),
            "progress evidence fingerprint must not be empty"
        );
        ensure!(
            !observation.apis.is_empty(),
            "progress run must contain at least one API"
        );
        for (api, result) in &observation.apis {
            ensure!(!api.is_empty(), "progress API key must not be empty");
            ensure!(
                result.cases.executed > 0,
                "progress API {api:?} must execute at least one case"
            );
            ensure!(
                result.cases.passed <= result.cases.executed,
                "progress API {api:?} passed more cases than it executed"
            );
            ensure!(
                !result.passed || result.cases.passed == result.cases.executed,
                "passing progress API {api:?} must pass every executed case"
            );
        }

        if let Some(latest) = &self.latest_run
            && latest.key == observation.key
        {
            ensure!(
                latest.evidence_fingerprint == observation.evidence_fingerprint,
                "progress run {:?} was already counted with different evidence",
                observation.key
            );
            return Ok(false);
        }

        let scope = observation.apis.keys().cloned().collect::<Vec<_>>();
        let same_scope = self
            .latest_run
            .as_ref()
            .is_some_and(|latest| latest.scope == scope);
        let cases =
            observation
                .apis
                .values()
                .fold(LatestCounts::default(), |mut counts, result| {
                    counts.executed = counts.executed.saturating_add(result.cases.executed);
                    counts.passed = counts.passed.saturating_add(result.cases.passed);
                    counts
                });
        let passed_apis = observation
            .apis
            .values()
            .filter(|result| result.passed)
            .count() as u64;
        let passed = passed_apis == observation.apis.len() as u64;

        self.totals.runs.executed = self.totals.runs.executed.saturating_add(1);
        self.totals.runs.passed = self.totals.runs.passed.saturating_add(u64::from(passed));
        self.totals.cases.executed = self.totals.cases.executed.saturating_add(cases.executed);
        self.totals.cases.passed = self.totals.cases.passed.saturating_add(cases.passed);

        if passed {
            if !same_scope {
                self.success_streak = SuccessStreak::default();
            }
            self.success_streak.runs = self.success_streak.runs.saturating_add(1);
            self.success_streak.cases = self.success_streak.cases.saturating_add(cases.executed);
        } else {
            self.success_streak = SuccessStreak::default();
        }

        for (api, result) in &observation.apis {
            let progress = self.apis.entry(api.clone()).or_default();
            progress.totals.runs.executed = progress.totals.runs.executed.saturating_add(1);
            progress.totals.runs.passed = progress
                .totals
                .runs
                .passed
                .saturating_add(u64::from(result.passed));
            progress.totals.cases.executed = progress
                .totals
                .cases
                .executed
                .saturating_add(result.cases.executed);
            progress.totals.cases.passed = progress
                .totals
                .cases
                .passed
                .saturating_add(result.cases.passed);
            if result.passed {
                progress.success_streak.runs = progress.success_streak.runs.saturating_add(1);
                progress.success_streak.cases = progress
                    .success_streak
                    .cases
                    .saturating_add(result.cases.executed);
            } else {
                progress.success_streak = SuccessStreak::default();
            }
        }
        self.totals.apis.total = self.apis.len() as u64;
        self.updated_at = observation.finished_at;
        self.latest_run = Some(LatestRun {
            key: observation.key,
            evidence_fingerprint: observation.evidence_fingerprint,
            number: self.totals.runs.executed,
            passed,
            cases,
            apis: LatestCounts {
                executed: observation.apis.len() as u64,
                passed: passed_apis,
            },
            scope,
        });
        Ok(true)
    }
}

pub(crate) fn load(path: &Path, stage: VerificationStage) -> Result<Option<ProgressReport>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect progress {}", path.display()));
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "progress must be a regular file and not a symlink: {}",
        path.display()
    );
    let payload =
        fs::read(path).with_context(|| format!("failed to read progress {}", path.display()))?;
    let report: ProgressReport = serde_yaml::from_slice(&payload)
        .with_context(|| format!("failed to parse progress {}", path.display()))?;
    ensure!(
        report.version == PROGRESS_VERSION,
        "unsupported {:?} progress version {}",
        report.stage,
        report.version
    );
    ensure!(
        report.stage == stage,
        "{} contains {:?} progress, expected {:?}",
        path.display(),
        report.stage,
        stage
    );
    Ok(Some(report))
}

pub(crate) fn write(path: &Path, report: &ProgressReport) -> Result<()> {
    let mut payload = serde_yaml::to_string(report)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress must be a regular file and not a symlink: {}",
                path.display()
            );
            write_atomic(path, &payload)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_atomic(path, &payload),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect progress {}", path.display()))
        }
    }
}

pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn observation(key: &str, apis: &[(&str, u64, u64)]) -> ProgressObservation {
        ProgressObservation {
            key: key.to_string(),
            evidence_fingerprint: format!("fingerprint-{key}"),
            finished_at: format!("2026-07-31T00:00:0{}Z", key.len()),
            apis: apis
                .iter()
                .map(|(api, executed, passed)| {
                    (
                        (*api).to_string(),
                        ApiObservation {
                            cases: LatestCounts {
                                executed: *executed,
                                passed: *passed,
                            },
                            passed: executed == passed,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn tracks_totals_and_resets_global_and_api_streaks_on_failure() {
        let mut report = ProgressReport::new(VerificationStage::Comparison);
        report
            .apply(observation("1", &[("GET /users", 100, 100)]))
            .unwrap();
        report
            .apply(observation("2", &[("GET /users", 100, 100)]))
            .unwrap();

        assert_eq!(report.totals.runs.executed, 2);
        assert_eq!(report.totals.runs.passed, 2);
        assert_eq!(report.success_streak.runs, 2);
        assert_eq!(report.success_streak.cases, 200);
        assert_eq!(report.apis["GET /users"].success_streak.runs, 2);

        report
            .apply(observation("3", &[("GET /users", 100, 99)]))
            .unwrap();

        assert_eq!(report.totals.runs.executed, 3);
        assert_eq!(report.totals.cases.passed, 299);
        assert_eq!(report.success_streak.runs, 0);
        assert_eq!(report.success_streak.cases, 0);
        assert_eq!(report.apis["GET /users"].success_streak.runs, 0);
    }

    #[test]
    fn one_failed_api_resets_global_streak_without_resetting_other_api() {
        let mut report = ProgressReport::new(VerificationStage::Replay);
        report
            .apply(observation(
                "1",
                &[("GET /users", 50, 50), ("GET /friends", 50, 50)],
            ))
            .unwrap();
        report
            .apply(observation(
                "2",
                &[("GET /users", 50, 50), ("GET /friends", 50, 49)],
            ))
            .unwrap();

        assert_eq!(report.success_streak.runs, 0);
        assert_eq!(report.apis["GET /users"].success_streak.runs, 2);
        assert_eq!(report.apis["GET /friends"].success_streak.runs, 0);
    }

    #[test]
    fn changed_global_scope_starts_a_new_streak() {
        let mut report = ProgressReport::new(VerificationStage::Comparison);
        report
            .apply(observation("1", &[("GET /users", 100, 100)]))
            .unwrap();
        report
            .apply(observation(
                "2",
                &[("GET /users", 100, 100), ("GET /friends", 100, 100)],
            ))
            .unwrap();

        assert_eq!(report.success_streak.runs, 1);
        assert_eq!(report.success_streak.cases, 200);
        assert_eq!(report.apis["GET /users"].success_streak.runs, 2);
    }

    #[test]
    fn duplicate_evidence_is_idempotent_and_conflicting_evidence_is_rejected() {
        let mut report = ProgressReport::new(VerificationStage::Comparison);
        let current = observation("1", &[("GET /users", 100, 100)]);
        assert!(report.apply(current.clone()).unwrap());
        assert!(!report.apply(current).unwrap());

        let mut conflicting = observation("1", &[("GET /users", 100, 100)]);
        conflicting.evidence_fingerprint = "other".to_string();
        assert!(report.apply(conflicting).is_err());
        assert_eq!(report.totals.runs.executed, 1);
    }

    #[test]
    fn round_trips_the_same_schema_for_both_stages() {
        let directory = tempdir().unwrap();
        for (name, stage) in [
            ("replay-progress.yaml", VerificationStage::Replay),
            ("comparison-progress.yaml", VerificationStage::Comparison),
        ] {
            let path = directory.path().join(name);
            let mut report = ProgressReport::new(stage);
            report
                .apply(observation("1", &[("GET /users", 100, 100)]))
                .unwrap();
            write(&path, &report).unwrap();
            let loaded = load(&path, stage).unwrap().unwrap();
            assert_eq!(loaded.stage, stage);
            assert_eq!(loaded.success_streak.cases, 100);
        }
    }
}
