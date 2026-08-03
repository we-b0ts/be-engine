use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::edit::{create_atomic, write_atomic};

pub(crate) const PROGRESS_VERSION: u8 = 1;
const MAX_COUNTED_RUNS: usize = 10_000;

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
    #[serde(default)]
    pub(crate) counted_runs: BTreeMap<String, String>,
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
            counted_runs: BTreeMap::new(),
            apis: BTreeMap::new(),
        }
    }

    pub(crate) fn apply(&mut self, observation: ProgressObservation) -> Result<bool> {
        self.validate_observation(&observation)?;

        if let Some(evidence_fingerprint) = self.counted_runs.get(&observation.key) {
            ensure!(
                evidence_fingerprint == &observation.evidence_fingerprint,
                "progress run {:?} was already counted with different evidence",
                observation.key
            );
            return Ok(false);
        }
        ensure!(
            self.counted_runs.len() < MAX_COUNTED_RUNS,
            "progress counted-run limit of {MAX_COUNTED_RUNS} was reached"
        );

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
        self.counted_runs.insert(
            observation.key.clone(),
            observation.evidence_fingerprint.clone(),
        );
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

    pub(crate) fn revise_latest(&mut self, observation: ProgressObservation) -> Result<bool> {
        self.validate_observation(&observation)?;
        ensure!(
            observation.apis.len() == 1,
            "only a focused single-API progress run can be revised"
        );
        let latest = self
            .latest_run
            .clone()
            .context("progress has no latest run to revise")?;
        ensure!(
            latest.key == observation.key,
            "only the latest progress run can be revised"
        );
        let (api_key, api_observation) = observation
            .apis
            .iter()
            .next()
            .expect("single-API observation is non-empty");
        ensure!(
            latest.scope == [api_key.clone()],
            "latest progress scope changed before revision"
        );
        if latest.evidence_fingerprint == observation.evidence_fingerprint {
            return Ok(false);
        }

        revise_success_counts(&mut self.totals.cases, latest.cases, api_observation.cases);
        self.totals.runs.passed = self
            .totals
            .runs
            .passed
            .saturating_sub(u64::from(latest.passed))
            .saturating_add(u64::from(api_observation.passed));
        revise_streak(
            &mut self.success_streak,
            latest.passed,
            api_observation.passed,
            latest.cases.executed,
            api_observation.cases.executed,
        );

        let api = self
            .apis
            .get_mut(api_key)
            .with_context(|| format!("latest progress API {api_key:?} is missing"))?;
        revise_success_counts(&mut api.totals.cases, latest.cases, api_observation.cases);
        api.totals.runs.passed = api
            .totals
            .runs
            .passed
            .saturating_sub(u64::from(latest.passed))
            .saturating_add(u64::from(api_observation.passed));
        revise_streak(
            &mut api.success_streak,
            latest.passed,
            api_observation.passed,
            latest.cases.executed,
            api_observation.cases.executed,
        );

        self.updated_at = observation.finished_at;
        self.counted_runs.insert(
            observation.key.clone(),
            observation.evidence_fingerprint.clone(),
        );
        self.latest_run = Some(LatestRun {
            key: observation.key,
            evidence_fingerprint: observation.evidence_fingerprint,
            number: latest.number,
            passed: api_observation.passed,
            cases: api_observation.cases,
            apis: LatestCounts {
                executed: 1,
                passed: u64::from(api_observation.passed),
            },
            scope: vec![api_key.clone()],
        });
        Ok(true)
    }

    fn validate_observation(&self, observation: &ProgressObservation) -> Result<()> {
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
        Ok(())
    }
}

fn revise_success_counts(
    totals: &mut SuccessCounts,
    previous: LatestCounts,
    current: LatestCounts,
) {
    totals.executed = totals
        .executed
        .saturating_sub(previous.executed)
        .saturating_add(current.executed);
    totals.passed = totals
        .passed
        .saturating_sub(previous.passed)
        .saturating_add(current.passed);
}

fn revise_streak(
    streak: &mut SuccessStreak,
    previous_passed: bool,
    current_passed: bool,
    previous_cases: u64,
    current_cases: u64,
) {
    match (previous_passed, current_passed) {
        (true, true) => {
            streak.cases = streak
                .cases
                .saturating_sub(previous_cases)
                .saturating_add(current_cases);
        }
        (false, true) => {
            streak.runs = 1;
            streak.cases = current_cases;
        }
        (true, false) => *streak = SuccessStreak::default(),
        (false, false) => {}
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
    let mut report: ProgressReport = serde_yaml::from_slice(&payload)
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
    ensure!(
        report.counted_runs.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted runs",
        path.display()
    );
    if let Some(latest) = &report.latest_run {
        match report.counted_runs.get(&latest.key) {
            Some(evidence_fingerprint) => ensure!(
                evidence_fingerprint == &latest.evidence_fingerprint,
                "{} contains conflicting evidence for its latest run",
                path.display()
            ),
            None if report.counted_runs.is_empty() => {
                report
                    .counted_runs
                    .insert(latest.key.clone(), latest.evidence_fingerprint.clone());
            }
            None => {
                anyhow::bail!(
                    "{} does not include its latest run in counted_runs",
                    path.display()
                );
            }
        }
    }
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
        let first = observation("1", &[("GET /users", 100, 100)]);
        assert!(report.apply(first.clone()).unwrap());
        assert!(
            report
                .apply(observation("2", &[("GET /users", 100, 100)]))
                .unwrap()
        );
        assert!(!report.apply(first).unwrap());

        let mut conflicting = observation("1", &[("GET /users", 100, 100)]);
        conflicting.evidence_fingerprint = "other".to_string();
        assert!(report.apply(conflicting).is_err());
        assert_eq!(report.totals.runs.executed, 2);
    }

    #[test]
    fn revises_latest_focused_observation_without_counting_a_new_run() {
        let mut report = ProgressReport::new(VerificationStage::Replay);
        report
            .apply(observation("1", &[("GET /users", 100, 100)]))
            .unwrap();
        report
            .apply(observation("2", &[("GET /users", 100, 98)]))
            .unwrap();
        let mut revised = observation("2", &[("GET /users", 100, 100)]);
        revised.evidence_fingerprint = "reclassified-fingerprint-2".to_string();

        assert!(report.revise_latest(revised).unwrap());

        assert_eq!(report.totals.runs.executed, 2);
        assert_eq!(report.totals.runs.passed, 2);
        assert_eq!(report.totals.cases.executed, 200);
        assert_eq!(report.totals.cases.passed, 200);
        assert_eq!(report.success_streak.runs, 1);
        assert_eq!(report.success_streak.cases, 100);
        assert_eq!(report.apis["GET /users"].totals.runs.executed, 2);
        assert_eq!(report.apis["GET /users"].totals.runs.passed, 2);
        assert_eq!(
            report.latest_run.as_ref().unwrap().evidence_fingerprint,
            "reclassified-fingerprint-2"
        );
    }

    #[test]
    fn refuses_to_revise_a_non_latest_progress_run() {
        let mut report = ProgressReport::new(VerificationStage::Replay);
        report
            .apply(observation("1", &[("GET /users", 1, 0)]))
            .unwrap();
        report
            .apply(observation("2", &[("GET /users", 1, 0)]))
            .unwrap();
        let mut stale = observation("1", &[("GET /users", 1, 1)]);
        stale.evidence_fingerprint = "reclassified-fingerprint-1".to_string();

        assert!(
            report
                .revise_latest(stale)
                .unwrap_err()
                .to_string()
                .contains("only the latest")
        );
    }

    #[test]
    fn rejects_new_runs_when_the_idempotency_ledger_is_full() {
        let mut report = ProgressReport::new(VerificationStage::Replay);
        report.counted_runs = (0..MAX_COUNTED_RUNS)
            .map(|index| (format!("run-{index}"), format!("evidence-{index}")))
            .collect();

        let error = report
            .apply(observation("new", &[("GET /users", 1, 1)]))
            .unwrap_err();

        assert!(error.to_string().contains("counted-run limit"));
        assert_eq!(report.totals.runs.executed, 0);
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
            assert_eq!(
                loaded.counted_runs.get("1").map(String::as_str),
                Some("fingerprint-1")
            );
        }
    }

    #[test]
    fn loading_an_older_report_seeds_the_latest_run_in_the_ledger() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("replay-progress.yaml");
        let mut report = ProgressReport::new(VerificationStage::Replay);
        let first = observation("1", &[("GET /users", 100, 100)]);
        report.apply(first.clone()).unwrap();
        let payload = serde_yaml::to_string(&report).unwrap();
        let legacy_payload = payload
            .lines()
            .filter(|line| !line.starts_with("counted_runs:") && !line.starts_with("  '1':"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, legacy_payload).unwrap();

        let mut loaded = load(&path, VerificationStage::Replay).unwrap().unwrap();

        assert!(!loaded.apply(first).unwrap());
        assert_eq!(loaded.totals.runs.executed, 1);
    }
}
