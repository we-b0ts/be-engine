use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::edit::{create_atomic, write_atomic};

mod ledger;

pub(crate) const PROGRESS_VERSION: u8 = 2;
const MIN_SUPPORTED_PROGRESS_VERSION: u8 = 1;
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
    #[serde(default, skip_serializing)]
    pub(crate) counted_runs: BTreeMap<String, String>,
    pub(crate) apis: BTreeMap<String, ProgressApi>,
    #[serde(skip)]
    pub(crate) requires_persistence: bool,
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
            requires_persistence: false,
        }
    }

    pub(crate) fn requires_persistence(&self) -> bool {
        self.requires_persistence
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
        (MIN_SUPPORTED_PROGRESS_VERSION..=PROGRESS_VERSION).contains(&report.version),
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
    let schema_migration = report.version != PROGRESS_VERSION;
    report.version = PROGRESS_VERSION;
    let embedded_counted_runs = !report.counted_runs.is_empty();
    let persisted_counted_runs = ledger::load(path, stage)?;
    merge_counted_runs(path, &mut report.counted_runs, persisted_counted_runs)?;
    report.requires_persistence = schema_migration || embedded_counted_runs;
    if let Some(latest) = &report.latest_run {
        match report.counted_runs.get(&latest.key) {
            Some(evidence_fingerprint) => ensure!(
                evidence_fingerprint == &latest.evidence_fingerprint,
                "{} contains conflicting evidence for its latest run",
                path.display()
            ),
            None => {
                report
                    .counted_runs
                    .insert(latest.key.clone(), latest.evidence_fingerprint.clone());
                report.requires_persistence = true;
            }
        }
    }
    ensure!(
        report.counted_runs.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted runs",
        path.display()
    );
    Ok(Some(report))
}

pub(crate) fn write(path: &Path, report: &ProgressReport) -> Result<()> {
    ensure!(
        report.version == PROGRESS_VERSION,
        "cannot write unsupported {:?} progress version {}",
        report.stage,
        report.version
    );
    let recovery_payload = ledger::recovery_payload(report)?;
    write_payload(path, &recovery_payload)?;
    ledger::write(path, report.stage, &report.counted_runs)?;
    let public_payload = yaml_payload(report)?;
    write_payload(path, &public_payload)
}

fn yaml_payload(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut payload = serde_yaml::to_string(value)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    Ok(payload)
}

fn write_payload(path: &Path, payload: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress must be a regular file and not a symlink: {}",
                path.display()
            );
            write_atomic(path, payload)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_atomic(path, payload),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect progress {}", path.display()))
        }
    }
}

fn merge_counted_runs(
    progress_path: &Path,
    destination: &mut BTreeMap<String, String>,
    source: BTreeMap<String, String>,
) -> Result<()> {
    for (key, evidence_fingerprint) in source {
        match destination.get(&key) {
            Some(embedded_fingerprint) => ensure!(
                embedded_fingerprint == &evidence_fingerprint,
                "{} contains conflicting counted-run evidence for {:?}",
                progress_path.display(),
                key
            ),
            None => {
                destination.insert(key, evidence_fingerprint);
            }
        }
    }
    Ok(())
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
mod tests;
