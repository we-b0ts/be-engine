use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::edit::{create_atomic, write_atomic};

mod epoch;
mod ledger;
mod revision;

pub(crate) use epoch::begin as begin_epoch;

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
    #[serde(default, skip_serializing)]
    pub(crate) counted_observations: BTreeMap<String, CountedObservation>,
    #[serde(default, skip_serializing)]
    pub(crate) observation_baseline: Option<ProgressBaseline>,
    pub(crate) apis: BTreeMap<String, ProgressApi>,
    #[serde(skip)]
    pub(crate) requires_persistence: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressTotals {
    pub(crate) runs: SuccessCounts,
    pub(crate) cases: SuccessCounts,
    pub(crate) apis: ApiCounts,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessCounts {
    pub(crate) executed: u64,
    pub(crate) passed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiCounts {
    pub(crate) total: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessStreak {
    pub(crate) runs: u64,
    pub(crate) cases: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LatestCounts {
    pub(crate) executed: u64,
    #[serde(default, alias = "successful")]
    pub(crate) passed: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressApi {
    pub(crate) totals: ApiTotals,
    pub(crate) success_streak: SuccessStreak,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiTotals {
    pub(crate) runs: SuccessCounts,
    pub(crate) cases: SuccessCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProgressObservation {
    pub(crate) key: String,
    pub(crate) evidence_fingerprint: String,
    pub(crate) finished_at: String,
    pub(crate) apis: BTreeMap<String, ApiObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApiObservation {
    pub(crate) cases: LatestCounts,
    pub(crate) passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CountedObservation {
    pub(crate) number: u64,
    pub(crate) observation: ProgressObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgressBaseline {
    pub(crate) number: u64,
    pub(crate) updated_at: String,
    pub(crate) totals: ProgressTotals,
    pub(crate) success_streak: SuccessStreak,
    pub(crate) latest_run: Option<LatestRun>,
    pub(crate) apis: BTreeMap<String, ProgressApi>,
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
            counted_observations: BTreeMap::new(),
            observation_baseline: None,
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

        if self.counted_observations.is_empty()
            && !self.counted_runs.is_empty()
            && self.observation_baseline.is_none()
        {
            self.observation_baseline = Some(self.current_baseline());
        }
        let number = self.totals.runs.executed.saturating_add(1);
        self.apply_aggregate(&observation, number);
        self.counted_runs.insert(
            observation.key.clone(),
            observation.evidence_fingerprint.clone(),
        );
        self.counted_observations.insert(
            observation.key.clone(),
            CountedObservation {
                number,
                observation,
            },
        );
        Ok(true)
    }

    fn apply_aggregate(&mut self, observation: &ProgressObservation, number: u64) {
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
        self.updated_at.clone_from(&observation.finished_at);
        self.latest_run = Some(LatestRun {
            key: observation.key.clone(),
            evidence_fingerprint: observation.evidence_fingerprint.clone(),
            number,
            passed,
            cases,
            apis: LatestCounts {
                executed: observation.apis.len() as u64,
                passed: passed_apis,
            },
            scope,
        });
    }

    fn current_baseline(&self) -> ProgressBaseline {
        ProgressBaseline {
            number: self.totals.runs.executed,
            updated_at: self.updated_at.clone(),
            totals: self.totals.clone(),
            success_streak: self.success_streak,
            latest_run: self.latest_run.clone(),
            apis: self.apis.clone(),
        }
    }

    fn validate_observation_history(&self) -> Result<()> {
        let mut observations = self.counted_observations.values().collect::<Vec<_>>();
        observations.sort_by_key(|counted| counted.number);
        let baseline_number = self
            .observation_baseline
            .as_ref()
            .map_or(0, |baseline| baseline.number);
        for (index, counted) in observations.iter().enumerate() {
            ensure!(
                counted.number == baseline_number + index as u64 + 1,
                "progress observation ledger has a missing or duplicate run number"
            );
            ensure!(
                self.counted_runs.get(&counted.observation.key)
                    == Some(&counted.observation.evidence_fingerprint),
                "progress observation ledger conflicts with counted-run evidence"
            );
        }
        ensure!(
            baseline_number + observations.len() as u64 == self.totals.runs.executed,
            "progress observation ledger does not reach the current aggregate"
        );
        Ok(())
    }

    fn rebuild_aggregates(&mut self) -> Result<()> {
        self.validate_observation_history()?;
        let mut observations = self
            .counted_observations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        observations.sort_by_key(|counted| counted.number);
        if let Some(baseline) = &self.observation_baseline {
            self.updated_at.clone_from(&baseline.updated_at);
            self.totals = baseline.totals.clone();
            self.success_streak = baseline.success_streak;
            self.latest_run.clone_from(&baseline.latest_run);
            self.apis.clone_from(&baseline.apis);
        } else {
            self.updated_at.clear();
            self.totals = ProgressTotals::default();
            self.success_streak = SuccessStreak::default();
            self.latest_run = None;
            self.apis.clear();
        }
        for counted in &observations {
            self.apply_aggregate(&counted.observation, counted.number);
        }
        Ok(())
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
    let persisted_ledger = ledger::load(path, stage)?;
    merge_counted_runs(
        path,
        &mut report.counted_runs,
        persisted_ledger.counted_runs,
    )?;
    merge_counted_observations(
        path,
        &mut report.counted_observations,
        persisted_ledger.counted_observations,
    )?;
    merge_observation_baseline(
        path,
        &mut report.observation_baseline,
        persisted_ledger.observation_baseline,
    )?;
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
    validate_counted_observations(path, &report)?;
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
    ledger::write(path, report)?;
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

fn merge_counted_observations(
    progress_path: &Path,
    destination: &mut BTreeMap<String, CountedObservation>,
    source: BTreeMap<String, CountedObservation>,
) -> Result<()> {
    for (key, observation) in source {
        match destination.get(&key) {
            Some(embedded) => ensure!(
                embedded == &observation,
                "{} contains conflicting counted observation for {:?}",
                progress_path.display(),
                key
            ),
            None => {
                destination.insert(key, observation);
            }
        }
    }
    Ok(())
}

fn validate_counted_observations(path: &Path, report: &ProgressReport) -> Result<()> {
    ensure!(
        report.counted_observations.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted observations",
        path.display()
    );
    let mut numbers = BTreeMap::new();
    for (key, counted) in &report.counted_observations {
        ensure!(
            counted.observation.key == *key,
            "{} contains a counted observation under the wrong key {:?}",
            path.display(),
            key
        );
        ensure!(
            report.counted_runs.get(key) == Some(&counted.observation.evidence_fingerprint),
            "{} contains conflicting evidence for counted observation {:?}",
            path.display(),
            key
        );
        ensure!(
            numbers.insert(counted.number, key).is_none(),
            "{} contains duplicate counted observation number {}",
            path.display(),
            counted.number
        );
    }
    if !report.counted_observations.is_empty() || report.observation_baseline.is_some() {
        report.validate_observation_history()?;
    }
    Ok(())
}

fn merge_observation_baseline(
    progress_path: &Path,
    destination: &mut Option<ProgressBaseline>,
    source: Option<ProgressBaseline>,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    match destination {
        Some(embedded) => ensure!(
            embedded == &source,
            "{} contains conflicting progress observation baselines",
            progress_path.display()
        ),
        None => *destination = Some(source),
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
