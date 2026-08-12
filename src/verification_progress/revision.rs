use anyhow::{Context, Result, ensure};

use super::{LatestCounts, ProgressObservation, ProgressReport, SuccessCounts, SuccessStreak};

impl ProgressReport {
    pub(crate) fn ensure_revisable(&self, key: &str) -> Result<()> {
        ensure!(
            self.counted_runs.contains_key(key),
            "progress run {key:?} has not been counted"
        );
        if self
            .latest_run
            .as_ref()
            .is_some_and(|latest| latest.key == key)
            || self.counted_observations.contains_key(key)
        {
            return Ok(());
        }
        anyhow::bail!(
            "historical progress run {key:?} cannot be revised because its observation ledger is incomplete"
        )
    }

    pub(crate) fn ensure_revisable_observation(
        &self,
        observation: &ProgressObservation,
    ) -> Result<()> {
        self.validate_observation(observation)?;
        ensure!(
            self.counted_runs.get(&observation.key) == Some(&observation.evidence_fingerprint),
            "progress run {:?} changed before revision",
            observation.key
        );
        self.ensure_revisable(&observation.key)?;
        if let Some(counted) = self.counted_observations.get(&observation.key) {
            ensure!(
                counted.observation == *observation,
                "progress run {:?} observation changed before revision",
                observation.key
            );
            return Ok(());
        }

        let latest = self
            .latest_run
            .as_ref()
            .context("progress has no latest run to revise")?;
        let (api_key, api) = observation
            .apis
            .iter()
            .next()
            .expect("validated focused observation is non-empty");
        ensure!(
            observation.apis.len() == 1
                && latest.key == observation.key
                && latest.scope == [api_key.clone()]
                && latest.passed == api.passed
                && latest.cases == api.cases,
            "latest progress aggregate changed before revision"
        );
        Ok(())
    }

    pub(crate) fn revise(
        &mut self,
        previous: ProgressObservation,
        current: ProgressObservation,
    ) -> Result<bool> {
        self.validate_observation(&previous)?;
        self.validate_observation(&current)?;
        ensure!(
            previous.apis.len() == 1 && current.apis.len() == 1,
            "only a focused single-API progress run can be revised"
        );
        ensure!(
            previous.key == current.key && previous.apis.keys().eq(current.apis.keys()),
            "focused progress identity changed before revision"
        );
        let persisted_fingerprint = self
            .counted_runs
            .get(&current.key)
            .with_context(|| format!("progress run {:?} has not been counted", current.key))?;
        if persisted_fingerprint == &current.evidence_fingerprint {
            return Ok(false);
        }
        ensure!(
            persisted_fingerprint == &previous.evidence_fingerprint,
            "progress run {:?} changed before revision",
            current.key
        );
        self.ensure_revisable_observation(&previous)?;

        if self.counted_observations.contains_key(&current.key) {
            self.validate_observation_history()?;
            let counted = self
                .counted_observations
                .get_mut(&current.key)
                .expect("complete observation history contains every counted run");
            ensure!(
                counted.observation == previous,
                "progress run {:?} observation changed before revision",
                current.key
            );
            counted.observation = current.clone();
            self.counted_runs
                .insert(current.key.clone(), current.evidence_fingerprint.clone());
            self.rebuild_aggregates()?;
            return Ok(true);
        }

        self.revise_legacy_latest(previous, current)
    }

    fn revise_legacy_latest(
        &mut self,
        previous: ProgressObservation,
        current: ProgressObservation,
    ) -> Result<bool> {
        let latest = self
            .latest_run
            .clone()
            .context("progress has no latest run to revise")?;
        ensure!(
            latest.key == current.key,
            "only the latest progress run can be revised"
        );
        let (api_key, previous_api) = previous
            .apis
            .iter()
            .next()
            .expect("single-API observation is non-empty");
        let current_api = current
            .apis
            .values()
            .next()
            .expect("single-API observation is non-empty");
        ensure!(
            latest.scope == [api_key.clone()],
            "latest progress scope changed before revision"
        );
        ensure!(
            latest.passed == previous_api.passed && latest.cases == previous_api.cases,
            "latest progress aggregate changed before revision"
        );

        revise_success_counts(
            &mut self.totals.cases,
            previous_api.cases,
            current_api.cases,
        );
        self.totals.runs.passed = self
            .totals
            .runs
            .passed
            .saturating_sub(u64::from(previous_api.passed))
            .saturating_add(u64::from(current_api.passed));
        revise_streak(
            &mut self.success_streak,
            previous_api.passed,
            current_api.passed,
            previous_api.cases.executed,
            current_api.cases.executed,
        );

        let api = self
            .apis
            .get_mut(api_key)
            .with_context(|| format!("latest progress API {api_key:?} is missing"))?;
        revise_success_counts(&mut api.totals.cases, previous_api.cases, current_api.cases);
        api.totals.runs.passed = api
            .totals
            .runs
            .passed
            .saturating_sub(u64::from(previous_api.passed))
            .saturating_add(u64::from(current_api.passed));
        revise_streak(
            &mut api.success_streak,
            previous_api.passed,
            current_api.passed,
            previous_api.cases.executed,
            current_api.cases.executed,
        );

        self.updated_at.clone_from(&current.finished_at);
        self.counted_runs
            .insert(current.key.clone(), current.evidence_fingerprint.clone());
        self.latest_run = Some(super::LatestRun {
            key: current.key,
            evidence_fingerprint: current.evidence_fingerprint,
            number: latest.number,
            passed: current_api.passed,
            cases: current_api.cases,
            apis: LatestCounts {
                executed: 1,
                passed: u64::from(current_api.passed),
            },
            scope: vec![api_key.clone()],
        });
        Ok(true)
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
