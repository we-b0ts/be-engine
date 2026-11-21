//! A Target may visit several Source calls with the same physical operation.
//! An unpaired Target stays visible and requires fresh Replay.
use crate::rewrite::unified_rule::preflight::PreflightMethods;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use crate::{policy::Surface, policy_evidence::WitnessRef};

use super::Preflight;

type Observation = (String, String, String);

#[derive(Default)]
pub struct Candidates {
    validated: BTreeSet<Observation>,
    rejected: BTreeMap<Observation, (Surface, String)>,
    deferred: BTreeSet<Observation>,
}

impl Candidates {
    pub fn defer(&mut self, witness: &WitnessRef) -> Result<()> {
        self.deferred.insert((
            witness.metadata.source.case_id.clone(),
            serde_json::to_string(&witness.metadata.resource)?,
            witness
                .target_observation_id
                .as_ref()
                .or(witness.target_sha256.as_ref())
                .context("deferred Target has no protected observation identity")?
                .clone(),
        ));
        Ok(())
    }
    pub fn observe(&mut self, witness: &WitnessRef, result: Result<usize>) -> Result<usize> {
        let observation = (
            witness.metadata.source.case_id.clone(),
            serde_json::to_string(&witness.metadata.resource)?,
            witness
                .target_observation_id
                .as_ref()
                .or(witness.target_sha256.as_ref())
                .context("dependency candidate has no protected Target observation identity")?
                .clone(),
        );
        match result {
            Ok(count) if count > 0 => {
                self.rejected.remove(&observation);
                self.validated.insert(observation);
                Ok(count)
            }
            Ok(_) => Ok(0),
            Err(_) => {
                if !self.validated.contains(&observation) {
                    self.rejected
                        .entry(observation)
                        .or_insert_with(|| (witness.metadata.surface, witness.id.clone()));
                }
                Ok(0)
            }
        }
    }

    pub fn finish(self, result: &mut Preflight) {
        for (id, (surface, witness)) in self.rejected {
            if !self.deferred.contains(&id) {
                result.defer_target_comparison(&id.0, surface, Some(&witness));
            }
        }
    }
}
