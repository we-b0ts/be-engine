//! Prepare immutable event postings once, outside Target request execution.
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use traffic_model::trace::{CaptureEvent, RecordedEvent};
use traffic_replay::SequenceCatalog;
use traffic_replay::SequenceRuntime;

pub(super) use traffic_replay::request_wait::MissingDependency;

impl<P: super::ReplayProtocolSet> traffic_replay::request::ExecutionState
    for super::RuntimeState<P>
{
    type Observation = super::admission::RequestAdmission;

    fn is_finalized(&self) -> bool {
        self.finalized_at.is_some()
    }
    fn cancel_reason(&self, observation: &Self::Observation) -> Option<&'static str> {
        observation.cancel_reason(self)
    }
    fn sequence_wait(&self, bytes: usize) -> Option<traffic_replay::request_wait::RequestWait> {
        let scopes =
            self.active_sequence
                .clone()
                .map(|runtime| (true, runtime))
                .into_iter()
                .chain(
                    self.run_sequence.as_ref().into_iter().flat_map(|run| {
                        run.runtimes.iter().cloned().map(|runtime| (false, runtime))
                    }),
                );
        traffic_replay::request_wait::RequestWait::new(scopes, bytes)
    }
    fn record_missing(
        &mut self,
        observation: &Self::Observation,
        waiter: &traffic_replay::request_wait::RequestWait,
    ) {
        self.sequence_missing
            .extend(waiter.diagnose(self.admission_epoch, observation.case.as_deref()));
    }
}

pub(crate) use traffic_replay::SequenceBinding as Binding;

impl<P: super::ReplayProtocolSet> super::RuntimeState<P> {
    pub(super) fn activate_sequence(&mut self, case: Option<&str>) {
        if let Some(runtime) = self.active_sequence.take()
            && !runtime.complete()
        {
            if let Some(expected) = runtime.missing_request(self.admission_epoch) {
                self.sequence_missing.push(MissingDependency {
                    case_id: self.active_case_id.clone(),
                    expected,
                    ownership_revision: self.admission_epoch,
                    attribution_review: "required",
                });
            }
            runtime.abort();
        }
        self.active_sequence = case
            .and_then(|case| self.case_execution_plans.get(case))
            .and_then(|plan| plan.sequence.clone())
            .map(SequenceRuntime::new);
        let run = self
            .run_sequence
            .as_ref()
            .map(|run| run.runtimes.as_slice())
            .unwrap_or_default();
        let bindings = self
            .active_sequence
            .as_ref()
            .map(|runtime| {
                self.case_execution_plans[case.expect("prepared Case sequence")]
                    .native
                    .protocols
                    .iter()
                    .map(|(protocol, inventory)| {
                        (
                            *protocol,
                            Binding::new(runtime.clone(), inventory.sequence.iter().copied()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.protocols.bind_case_sequence(bindings, run);
        self.native.core.lifecycle.sequence =
            self.active_sequence
                .as_ref()
                .map(|runtime| {
                    let plan = &self.case_execution_plans[case.expect("prepared Case sequence")];
                    Binding::new(
                        runtime.clone(),
                        plan.native.registered.iter().filter_map(|index| {
                            Some((*index, self.native.recorded_sequence(*index)?))
                        }),
                    )
                })
                .unwrap_or_default();
        self.attach_run_sequence();
    }
}

mod run;
pub(super) use run::RunBindings;

pub(super) fn load(source: &Path) -> Result<Option<Arc<SequenceCatalog>>> {
    let Some(root) = crate::dependency_index::recording::root(source) else {
        return Ok(None);
    };
    let compact = root.join(traffic_model::compact::EVENTS);
    let (path, compact) = if compact.exists() {
        (compact, true)
    } else {
        (root.join("dependency-lifecycle.jsonl"), false)
    };
    let input =
        std::fs::File::open(path).context("recording has no ordered dependency event journal")?;
    let records =
        BufReader::new(input)
            .lines()
            .map(|line| -> Result<RecordedEvent<CaptureEvent>> {
                let line = line?;
                if compact {
                    traffic_model::compact::decode_event(&line)
                } else {
                    Ok(serde_json::from_str(&line)?)
                }
            });
    SequenceCatalog::try_prepare(records).map(Some)
}
