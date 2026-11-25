use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use traffic_replay::{EventKind, SequencePlan};

const MAX_PLAN_BYTES: usize = 1_048_576;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    cases: BTreeMap<String, Vec<Checkpoint>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "CheckpointFields")]
pub(super) struct Checkpoint {
    pub(super) site: String,
    pub(super) stream: String,
    pub(super) occurrence: u64,
    pub(super) consumed_through: u64,
    pub(super) anchor: Anchor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointFields {
    site: String,
    stream: String,
    occurrence: u64,
    consumed_through: u64,
    before_request: Option<u64>,
    before_event: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Anchor {
    BeforeRequest(u64),
    BeforeEvent(u64),
}

impl TryFrom<CheckpointFields> for Checkpoint {
    type Error = &'static str;

    fn try_from(fields: CheckpointFields) -> Result<Self, Self::Error> {
        let anchor = match (fields.before_request, fields.before_event) {
            (Some(sequence), None) => Anchor::BeforeRequest(sequence),
            (None, Some(sequence)) => Anchor::BeforeEvent(sequence),
            _ => {
                return Err(
                    "a Replay timer needs exactly one before_request or before_event anchor",
                );
            }
        };
        Ok(Self {
            site: fields.site,
            stream: fields.stream,
            occurrence: fields.occurrence,
            consumed_through: fields.consumed_through,
            anchor,
        })
    }
}

impl Anchor {
    pub(super) fn sequence(self) -> u64 {
        match self {
            Self::BeforeRequest(sequence) | Self::BeforeEvent(sequence) => sequence,
        }
    }

    pub(super) fn kind(self) -> EventKind {
        match self {
            Self::BeforeRequest(_) => EventKind::Request,
            Self::BeforeEvent(_) => EventKind::SessionSourceExit,
        }
    }
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
            let mut anchors = BTreeSet::new();
            let mut timers = BTreeSet::new();
            for checkpoint in checkpoints {
                ensure!(
                    valid_name(&checkpoint.site)
                        && valid_name(&checkpoint.stream)
                        && checkpoint.occurrence != 0
                        && checkpoint.anchor.sequence() != 0,
                    "invalid Replay timer checkpoint for Case {case}"
                );
                ensure!(
                    anchors.insert(checkpoint.anchor.sequence())
                        && timers.insert((
                            &checkpoint.site,
                            &checkpoint.stream,
                            checkpoint.occurrence
                        )),
                    "duplicate Replay timer identity or anchor for Case {case}"
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
                matches!(checkpoint.anchor, Anchor::BeforeRequest(_)),
                "before_event Replay timer anchors require session Replay"
            );
            ensure!(
                sequence.is_some_and(|plan| plan.is_request_sequence(checkpoint.anchor.sequence())),
                "Replay timer anchor {} is not a request in the Source sequence for Case {case}",
                checkpoint.anchor.sequence()
            );
        }
        Ok(())
    }

    pub(super) fn validate_session(&self, scope: &str, sequence: &SequencePlan) -> Result<()> {
        ensure!(
            self.cases.keys().all(|case| case == scope),
            "session Replay timer plan must use the {scope:?} scope"
        );
        for checkpoint in self.checkpoints(scope) {
            let anchor = checkpoint.anchor;
            ensure!(
                sequence
                    .event(anchor.sequence())
                    .is_some_and(|event| event.kind == anchor.kind()),
                "Replay timer anchor {} does not identify a {:?} in the Source session",
                anchor.sequence(),
                anchor.kind()
            );
        }
        Ok(())
    }

    pub(super) fn stream_session_anchors(&self, scope: &str) -> Result<BTreeMap<u64, EventKind>> {
        ensure!(
            self.cases.keys().all(|case| case == scope),
            "session Replay timer plan must use the {scope:?} scope"
        );
        Ok(self
            .checkpoints(scope)
            .iter()
            .map(|step| (step.anchor.sequence(), step.anchor.kind()))
            .collect())
    }
}

pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}
