use anyhow::{Context, Result, ensure};

use super::{
    CountedObservation, LatestCounts, ProgressObservation, ProgressReport, SuccessCounts,
    SuccessStreak, failed_apis, observation_passed,
};

impl ProgressReport {
    pub(crate) fn upsert_logical_run(
        &mut self,
        mut current: ProgressObservation,
        legacy_key_prefix: Option<&str>,
        authoritative_scope: bool,
    ) -> Result<bool> {
        self.validate_observation(&current)?;

        if let Some(previous) = self
            .counted_observations
            .get(&current.key)
            .map(|counted| counted.observation.clone())
        {
            ensure!(
                current.apis.iter().all(|(api, result)| {
                    previous
                        .apis
                        .get(api)
                        .is_none_or(|recorded| recorded.cases.executed == result.cases.executed)
                }),
                "logical progress run {:?} changed its recorded API case inventory",
                current.key
            );
            if !previous.finalized && !authoritative_scope {
                let mut merged = previous.clone();
                merged.evidence_fingerprint = current.evidence_fingerprint.clone();
                merged.finished_at.clone_from(&current.finished_at);
                for (api, result) in current.apis {
                    merged.apis.insert(api, result);
                }
                merged.finalized =
                    current.finalized && merged.apis.values().all(|api| api.finalized);
                merged.passed = merged
                    .finalized
                    .then(|| merged.apis.values().all(|api| api.passed));
                current = merged;
            }
            if !authoritative_scope {
                ensure!(
                    previous.apis.iter().all(|(api, previous)| {
                        current.apis.get(api).is_some_and(|current| {
                            current.cases.executed == previous.cases.executed
                        })
                    }),
                    "logical progress run {:?} changed its recorded API case inventory",
                    current.key
                );
            }
            if previous.evidence_fingerprint == current.evidence_fingerprint {
                return Ok(false);
            }
            let counted = self
                .counted_observations
                .get_mut(&current.key)
                .expect("logical run observation disappeared during replacement");
            counted.streak_broken |= super::observation_failed(&current);
            counted.api_streak_broken.extend(failed_apis(&current));
            counted.observation = current.clone();
            self.counted_runs
                .insert(current.key.clone(), current.evidence_fingerprint.clone());
            self.rebuild_aggregates()?;
            return Ok(true);
        }

        let legacy_keys = self
            .counted_observations
            .iter()
            .filter(|(key, _)| legacy_key_prefix.is_some_and(|prefix| key.starts_with(prefix)))
            .map(|(key, counted)| (key.clone(), counted.number))
            .collect::<Vec<_>>();
        if legacy_keys.is_empty() {
            return self.apply(current);
        }
        let legacy_key_prefix = legacy_key_prefix
            .expect("non-empty legacy observation set requires its configured prefix");

        let first_legacy_number = legacy_keys
            .iter()
            .map(|(_, number)| *number)
            .min()
            .expect("non-empty legacy observation set has a first number");
        ensure!(
            self.counted_observations
                .values()
                .all(|counted| counted.number < first_legacy_number
                    || counted.observation.key.starts_with(legacy_key_prefix)),
            "legacy replay attempts for logical run {:?} are not the latest progress entries",
            current.key
        );
        let streak_broken = super::observation_failed(&current)
            || legacy_keys.iter().any(|(key, _)| {
                self.counted_observations.get(key).is_some_and(|counted| {
                    counted.streak_broken || !observation_passed(&counted.observation)
                })
            });
        let mut api_streak_broken = failed_apis(&current);
        for (key, _) in &legacy_keys {
            if let Some(counted) = self.counted_observations.get(key) {
                api_streak_broken.extend(counted.api_streak_broken.iter().cloned());
                api_streak_broken.extend(failed_apis(&counted.observation));
            }
        }

        self.counted_observations
            .retain(|key, _| !key.starts_with(legacy_key_prefix));
        self.counted_runs
            .retain(|key, _| !key.starts_with(legacy_key_prefix));
        self.counted_runs
            .insert(current.key.clone(), current.evidence_fingerprint.clone());
        self.counted_observations.insert(
            current.key.clone(),
            CountedObservation {
                number: first_legacy_number,
                streak_broken,
                api_streak_broken,
                observation: current,
            },
        );
        self.rebuild_aggregates()?;
        Ok(true)
    }

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
                same_source_observation(&counted.observation, observation),
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
                same_source_observation(&counted.observation, &previous),
                "progress run {:?} observation changed before revision",
                current.key
            );
            counted.streak_broken |= super::observation_failed(&current);
            counted.api_streak_broken.extend(failed_apis(&current));
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
            finalized: current.finalized,
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

fn same_source_observation(
    persisted: &ProgressObservation,
    supplied: &ProgressObservation,
) -> bool {
    persisted.key == supplied.key
        && persisted.evidence_fingerprint == supplied.evidence_fingerprint
        && persisted.finished_at == supplied.finished_at
        && persisted.passed == supplied.passed
        && persisted.apis.len() == supplied.apis.len()
        && persisted.apis.iter().all(|(api, persisted)| {
            supplied.apis.get(api).is_some_and(|supplied| {
                persisted.cases == supplied.cases && persisted.passed == supplied.passed
            })
        })
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
