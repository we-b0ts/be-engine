//! Recording-owned progress coverage assembled from actual Replay attempts.
use anyhow::{Result, ensure};

use super::{
    CountedObservation, ProgressObservation, ProgressReport, failed_apis, observation_passed,
};

impl ProgressReport {
    pub(crate) fn upsert_logical_run(
        &mut self,
        current: ProgressObservation,
        legacy_key_prefix: Option<&str>,
        authoritative_scope: bool,
    ) -> Result<bool> {
        let current = self.merge_logical_run_scope(current, authoritative_scope)?;

        if let Some(previous) = self
            .counted_observations
            .get(&current.key)
            .map(|counted| counted.observation.clone())
        {
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

    /// Preserve unfinished recording coverage outside a partial prepared inventory.
    fn merge_logical_run_scope(
        &self,
        mut current: ProgressObservation,
        authoritative_scope: bool,
    ) -> Result<ProgressObservation> {
        self.validate_observation(&current)?;
        let Some(previous) = self
            .counted_observations
            .get(&current.key)
            .map(|counted| &counted.observation)
        else {
            return Ok(current);
        };
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
            merged.evidence_fingerprint = current.evidence_fingerprint;
            merged.finished_at = current.finished_at;
            merged.apis.extend(current.apis);
            merged.finalized = current.finalized && merged.apis.values().all(|api| api.finalized);
            merged.passed = merged
                .finalized
                .then(|| merged.apis.values().all(|api| api.passed));
            current = merged;
        }
        if !authoritative_scope {
            ensure!(
                previous.apis.iter().all(|(api, previous)| {
                    current
                        .apis
                        .get(api)
                        .is_some_and(|current| current.cases.executed == previous.cases.executed)
                }),
                "logical progress run {:?} changed its recorded API case inventory",
                current.key
            );
        }
        Ok(current)
    }
}
