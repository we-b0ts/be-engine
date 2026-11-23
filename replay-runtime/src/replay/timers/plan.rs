use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use traffic_replay::SequencePlan;

const MAX_PLAN_BYTES: usize = 1_048_576;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    cases: BTreeMap<String, Vec<Checkpoint>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub(super) site: String,
    pub(super) stream: String,
    pub(super) occurrence: u64,
    pub(super) consumed_through: u64,
    pub(super) before_request: u64,
}

impl Plan {
    pub(super) async fn load(path: &Path) -> Result<Self> {
        let file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("open Replay timer plan {}", path.display()))?;
        let mut bytes = Vec::new();
        file.take(MAX_PLAN_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= MAX_PLAN_BYTES,
            "Replay timer plan is too large"
        );
        let plan: Self = serde_json::from_slice(&bytes).context("decode Replay timer plan")?;
        ensure!(!plan.cases.is_empty(), "Replay timer plan has no Cases");
        for (case, checkpoints) in &plan.cases {
            ensure!(
                valid_name(case) && !checkpoints.is_empty(),
                "invalid Case entry in Replay timer plan"
            );
            let mut requests = BTreeSet::new();
            let mut timers = BTreeSet::new();
            for checkpoint in checkpoints {
                ensure!(
                    valid_name(&checkpoint.site)
                        && valid_name(&checkpoint.stream)
                        && checkpoint.occurrence != 0
                        && checkpoint.before_request != 0,
                    "invalid Replay timer checkpoint for Case {case}"
                );
                ensure!(
                    requests.insert(checkpoint.before_request)
                        && timers.insert((
                            &checkpoint.site,
                            &checkpoint.stream,
                            checkpoint.occurrence
                        )),
                    "duplicate Replay timer identity or request anchor for Case {case}"
                );
            }
        }
        Ok(plan)
    }

    pub(super) fn checkpoints(&self, case: &str) -> &[Checkpoint] {
        self.cases.get(case).map_or(&[], Vec::as_slice)
    }

    pub(super) fn validate_case(&self, case: &str, sequence: Option<&SequencePlan>) -> Result<()> {
        for checkpoint in self.checkpoints(case) {
            ensure!(
                sequence.is_some_and(|plan| plan.is_request_sequence(checkpoint.before_request)),
                "Replay timer anchor {} is not a request in the Source sequence for Case {case}",
                checkpoint.before_request
            );
        }
        Ok(())
    }
}

pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}
