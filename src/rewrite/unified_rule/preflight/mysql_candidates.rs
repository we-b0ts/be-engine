//! A Target may visit several Source rows with the same statement structure.
//! Failed search edges remain protected, but only an unpaired Target is an error.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use crate::policy_evidence::WitnessRef;

type Observation = (String, String, String);

#[derive(Default)]
pub(super) struct Candidates {
    validated: BTreeSet<Observation>,
    rejected: BTreeMap<Observation, anyhow::Error>,
}

impl Candidates {
    pub(super) fn observe(&mut self, witness: &WitnessRef, result: Result<usize>) -> Result<usize> {
        let observation = (
            witness.metadata.source.case_id.clone(),
            serde_json::to_string(&witness.metadata.resource)?,
            witness
                .target_observation_id
                .as_ref()
                .or(witness.target_sha256.as_ref())
                .context("MySQL candidate has no protected Target observation identity")?
                .clone(),
        );
        match result {
            Ok(count) if count > 0 => {
                self.rejected.remove(&observation);
                self.validated.insert(observation);
                Ok(count)
            }
            Ok(_) => Ok(0),
            Err(error) => {
                if !self.validated.contains(&observation) {
                    self.rejected.entry(observation).or_insert(error);
                }
                Ok(0)
            }
        }
    }

    pub(super) fn finish(self) -> Result<()> {
        match self.rejected.into_values().next() {
            Some(error) => Err(error).context(
                "a related MySQL Target observation has no valid pair in the complete Source scope",
            ),
            None => Ok(()),
        }
    }
}
