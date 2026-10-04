use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::edit::{create_atomic, write_atomic};

mod epoch;
mod ledger;
mod public;
mod revision;

pub(crate) use epoch::begin as begin_epoch;

pub(crate) const PROGRESS_VERSION: u8 = 3;
const MIN_SUPPORTED_PROGRESS_VERSION: u8 = 1;
const MAX_COUNTED_RUNS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationStage {
    Progress,
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
    #[serde(default = "default_true")]
    pub(crate) finalized: bool,
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
    #[serde(default = "default_true")]
    pub(crate) finalized: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) passed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) success_streak: Option<SuccessStreak>,
    pub(crate) apis: BTreeMap<String, ApiObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApiObservation {
    pub(crate) cases: LatestCounts,
    #[serde(default = "default_true")]
    pub(crate) finalized: bool,
    pub(crate) passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) success_streak: Option<SuccessStreak>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CountedObservation {
    pub(crate) number: u64,
    #[serde(default)]
    pub(crate) streak_broken: bool,
    #[serde(default)]
    pub(crate) api_streak_broken: BTreeSet<String>,
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
        let streak_broken = observation_failed(&observation);
        let api_streak_broken = failed_apis(&observation);
        self.apply_aggregate(&observation, number, streak_broken, &api_streak_broken);
        self.counted_runs.insert(
            observation.key.clone(),
            observation.evidence_fingerprint.clone(),
        );
        self.counted_observations.insert(
            observation.key.clone(),
            CountedObservation {
                number,
                streak_broken,
                api_streak_broken,
                observation,
            },
        );
        Ok(true)
    }

    fn apply_aggregate(
        &mut self,
        observation: &ProgressObservation,
        number: u64,
        streak_broken: bool,
        api_streak_broken: &BTreeSet<String>,
    ) {
        let scope = observation.apis.keys().cloned().collect::<Vec<_>>();
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
        let passed = observation_passed(observation);

        self.totals.runs.executed = self.totals.runs.executed.saturating_add(1);
        self.totals.runs.passed = self
            .totals
            .runs
            .passed
            .saturating_add(u64::from(observation.finalized && passed));
        self.totals.cases.executed = self.totals.cases.executed.saturating_add(cases.executed);
        self.totals.cases.passed = self.totals.cases.passed.saturating_add(cases.passed);

        if observation.finalized && passed {
            if streak_broken {
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
            if result.finalized {
                progress.totals.runs.passed = progress
                    .totals
                    .runs
                    .passed
                    .saturating_add(u64::from(result.passed));
            }
            progress.totals.cases.executed = progress
                .totals
                .cases
                .executed
                .saturating_add(result.cases.executed);
            if result.finalized {
                progress.totals.cases.passed = progress
                    .totals
                    .cases
                    .passed
                    .saturating_add(result.cases.passed);
            }
            if result.finalized && result.passed {
                if api_streak_broken.contains(api) {
                    progress.success_streak = SuccessStreak::default();
                }
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
            finalized: observation.finalized,
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
        self.validate_observation_ledger()?;
        let baseline_number = self
            .observation_baseline
            .as_ref()
            .map_or(0, |baseline| baseline.number);
        ensure!(
            baseline_number + self.counted_observations.len() as u64 == self.totals.runs.executed,
            "progress observation ledger does not reach the current aggregate"
        );
        Ok(())
    }

    fn validate_observation_ledger(&self) -> Result<()> {
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
        Ok(())
    }

    fn rebuild_aggregates(&mut self) -> Result<()> {
        self.validate_observation_ledger()?;
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
            self.apply_aggregate(
                &counted.observation,
                counted.number,
                counted.streak_broken,
                &counted.api_streak_broken,
            );
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
            if !result.finalized {
                ensure!(
                    !result.passed && result.cases.passed == 0,
                    "pending progress API {api:?} must not contain verification results"
                );
            }
        }
        ensure!(
            observation.passed != Some(true)
                || observation.apis.values().all(|result| result.passed),
            "passing progress run must pass every executed API"
        );
        if !observation.finalized {
            ensure!(
                observation.passed.is_none(),
                "pending progress run must not contain a global verification result"
            );
        }
        Ok(())
    }
}

fn observation_passed(observation: &ProgressObservation) -> bool {
    observation
        .passed
        .unwrap_or_else(|| observation.apis.values().all(|result| result.passed))
}

fn default_true() -> bool {
    true
}

fn failed_apis(observation: &ProgressObservation) -> BTreeSet<String> {
    observation
        .apis
        .iter()
        .filter(|(_, result)| result.finalized && !result.passed)
        .map(|(api, _)| api.clone())
        .collect()
}

fn observation_failed(observation: &ProgressObservation) -> bool {
    (observation.finalized && !observation_passed(observation))
        || observation
            .apis
            .values()
            .any(|result| result.finalized && !result.passed)
}

pub(crate) fn load(path: &Path, stage: VerificationStage) -> Result<Option<ProgressReport>> {
    let public_report = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "progress must be a regular file and not a symlink: {}",
                path.display()
            );
            let payload = fs::read(path)
                .with_context(|| format!("failed to read progress {}", path.display()))?;
            let report = parse_progress_payload(&payload, stage)
                .with_context(|| format!("failed to parse progress {}", path.display()))?;
            Some(report)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect progress {}", path.display()));
        }
    };
    let persisted_ledger = ledger::load(path, stage)?;
    if public_report.is_none() && !persisted_ledger.exists {
        if stage == VerificationStage::Progress
            && let Some(report) = migrate_split_progress(path)?
        {
            return Ok(Some(report));
        }
        return Ok(None);
    }
    ensure!(
        public_report.is_some()
            || persisted_ledger.observation_baseline.is_some()
            || !persisted_ledger.counted_observations.is_empty()
            || persisted_ledger.counted_runs.is_empty(),
        "public progress {} is missing and its local ledger has no aggregate baseline",
        path.display()
    );
    let public_missing = public_report.is_none();
    let mut report = public_report.unwrap_or_else(|| ProgressReport::new(stage));
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
    normalize_failure_markers(&mut report.counted_observations);
    report.requires_persistence |= public_missing || schema_migration || embedded_counted_runs;
    if report.observation_baseline.is_some() || !report.counted_observations.is_empty() {
        let public_aggregate = public::Snapshot::from_report(&report);
        report.rebuild_aggregates()?;
        report.requires_persistence |= public::Snapshot::from_report(&report) != public_aggregate;
    }
    let epoch_baseline = epoch::merge_archived_baseline(path, stage, &mut report)?;
    report.requires_persistence |= epoch_baseline == Some(true);
    if epoch_baseline.is_none()
        && report.observation_baseline.is_none()
        && report.counted_observations.is_empty()
        && report.totals.runs.executed > 0
    {
        report.observation_baseline = Some(report.current_baseline());
        report.requires_persistence = true;
    }
    if let Some(latest) = &report.latest_run {
        let baseline_number = report
            .observation_baseline
            .as_ref()
            .map_or(0, |baseline| baseline.number);
        if epoch_baseline.is_none() || latest.number > baseline_number {
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
    }
    ensure!(
        report.counted_runs.len() <= MAX_COUNTED_RUNS,
        "{} contains more than {MAX_COUNTED_RUNS} counted runs",
        path.display()
    );
    validate_counted_observations(path, &report)?;
    Ok(Some(report))
}

fn migrate_split_progress(path: &Path) -> Result<Option<ProgressReport>> {
    let parent = path
        .parent()
        .context("progress path has no .traffic-e2e directory")?;
    let replay = load(
        &parent.join("replay-progress.yaml"),
        VerificationStage::Replay,
    )?;
    let comparison = load(
        &parent.join("comparison-progress.yaml"),
        VerificationStage::Comparison,
    )?;
    if replay.is_none() && comparison.is_none() {
        return Ok(None);
    }
    let mut merged = replay.unwrap_or_else(|| ProgressReport::new(VerificationStage::Progress));
    merged.stage = VerificationStage::Progress;
    merged.requires_persistence = true;
    Ok(Some(merged))
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
    let public_payload = yaml_payload(&public::Snapshot::from_report(report))?;
    write_payload(path, &public_payload)?;
    cleanup_split_public_progress(path)
}

pub(crate) fn synchronize(path: &Path, stage: VerificationStage) -> Result<bool> {
    let Some(report) = load(path, stage)? else {
        return Ok(false);
    };
    if !report.requires_persistence() {
        return Ok(false);
    }
    write(path, &report)?;
    Ok(true)
}

pub(crate) fn record_completed_batch(
    path: &Path,
    key: &str,
    recorded_at: String,
    apis: BTreeMap<String, u64>,
) -> Result<bool> {
    #[derive(Serialize)]
    struct RecordingEvidence<'a> {
        key: &'a str,
        apis: &'a BTreeMap<String, u64>,
    }

    let mut report = load(path, VerificationStage::Progress)?
        .unwrap_or_else(|| ProgressReport::new(VerificationStage::Progress));
    let requires_persistence = report.requires_persistence();
    if let Some(counted) = report.counted_observations.get(key) {
        ensure!(
            counted.observation.apis.len() == apis.len()
                && counted.observation.apis.iter().all(|(api, observation)| {
                    apis.get(api) == Some(&observation.cases.executed)
                }),
            "recorded progress batch {key:?} changed its API case inventory"
        );
        if requires_persistence {
            write(path, &report)?;
        }
        return Ok(false);
    }
    if report.counted_runs.contains_key(key) {
        if requires_persistence {
            write(path, &report)?;
        }
        return Ok(false);
    }
    let evidence_fingerprint = fingerprint(&serde_json::to_vec(&RecordingEvidence {
        key,
        apis: &apis,
    })?);
    let observation = ProgressObservation {
        key: key.to_string(),
        evidence_fingerprint,
        finished_at: recorded_at,
        finalized: false,
        passed: None,
        success_streak: None,
        apis: apis
            .into_iter()
            .map(|(api, executed)| {
                (
                    api,
                    ApiObservation {
                        cases: LatestCounts {
                            executed,
                            passed: 0,
                        },
                        finalized: false,
                        passed: false,
                        success_streak: None,
                    },
                )
            })
            .collect(),
    };
    report.apply(observation)?;
    write(path, &report)?;
    Ok(true)
}

fn yaml_payload(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut payload = serde_yaml::to_string(value)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    Ok(payload)
}

fn parse_progress_payload(payload: &[u8], stage: VerificationStage) -> Result<ProgressReport> {
    public::parse(payload, stage)
}

fn normalize_failure_markers(observations: &mut BTreeMap<String, CountedObservation>) {
    for counted in observations.values_mut() {
        counted.streak_broken |= observation_failed(&counted.observation)
            || (counted.observation.finalized
                && (counted.observation.success_streak.is_some_and(|streak| {
                    streak.runs == 1
                        && streak.cases
                            == counted
                                .observation
                                .apis
                                .values()
                                .map(|api| api.cases.executed)
                                .sum::<u64>()
                })));
        counted
            .api_streak_broken
            .extend(failed_apis(&counted.observation));
        if counted.observation.finalized {
            counted.api_streak_broken.extend(
                counted
                    .observation
                    .apis
                    .iter()
                    .filter(|(_, api)| {
                        api.success_streak.is_some_and(|streak| {
                            streak.runs == 1 && streak.cases == api.cases.executed
                        })
                    })
                    .map(|(api, _)| api.clone()),
            );
        }
    }
}

fn cleanup_split_public_progress(progress_path: &Path) -> Result<()> {
    if progress_path.file_name().and_then(|name| name.to_str()) != Some("progress.yaml") {
        return Ok(());
    }
    let parent = progress_path
        .parent()
        .context("progress path has no .traffic-e2e directory")?;
    for name in ["replay-progress.yaml", "comparison-progress.yaml"] {
        let legacy = parent.join(name);
        match fs::symlink_metadata(&legacy) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "legacy progress must be a regular file and not a symlink: {}",
                    legacy.display()
                );
                fs::remove_file(&legacy).with_context(|| {
                    format!("failed to remove migrated progress {}", legacy.display())
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect legacy progress {}", legacy.display())
                });
            }
        }
    }
    Ok(())
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
