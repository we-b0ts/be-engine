//! Prepare immutable event postings once, outside Target request execution.
use std::path::Path;
use std::sync::Arc;

use crate::dependency_index::recording::SourceEventIndex;
use anyhow::Result;
use traffic_replay::SequenceCatalog;
use traffic_replay::{SequencePlan, SequenceRuntime};

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
        if let Some(session) = &self.session_events {
            return traffic_replay::request_wait::RequestWait::with_grace(
                [(false, session.runtime.clone())],
                bytes,
                session.no_progress_timeout,
            );
        }
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
    fn sequence_runtime(&self, plan: Arc<traffic_replay::SequencePlan>) -> Arc<SequenceRuntime> {
        let cap = super::control::input_timing::source_fast_cap(self)
            .map(std::time::Duration::from_millis);
        SequenceRuntime::with_fast_gap_cap(plan, cap)
    }

    pub(super) fn activate_sequence(&mut self, case: Option<&str>) {
        if let Some(runtime) = self.active_sequence.take()
            && !runtime.complete()
        {
            if let Some(expected) = runtime.missing_request(self.admission_epoch) {
                self.sequence_missing.push(MissingDependency {
                    case_id: self.active_case_id.clone(),
                    expected,
                    ownership_revision: self.admission_epoch,
                });
            }
            runtime.abort();
        }
        self.timers.activate(case);
        self.active_sequence = case.and_then(|case| {
            let plan = self.case_execution_plans.get(case)?.sequence.clone()?;
            let cap = super::control::input_timing::source_fast_cap(self)
                .map(std::time::Duration::from_millis);
            Some(SequenceRuntime::with_request_gates(
                plan,
                cap,
                self.timers.event_gates(case),
            ))
        });
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

#[derive(Debug)]
pub(super) enum Source {
    Indexed(Box<SourceEventIndex>),
    Inline(Arc<SequenceCatalog>),
}

impl Source {
    pub(super) fn scope(
        &self,
        dependencies: impl IntoIterator<Item = u64>,
    ) -> Result<Arc<SequencePlan>> {
        match self {
            Self::Indexed(index) => SequencePlan::compile_recorded(index.selected(dependencies)?),
            Self::Inline(catalog) => catalog.scope(dependencies),
        }
    }
}

pub(super) fn load(source: &Path) -> Result<Option<Source>> {
    if crate::dependency_index::recording::root(source).is_none() {
        return Ok(None);
    }
    if let Some(index) = crate::dependency_index::recording::event_index_for_replay(source)? {
        return Ok(Some(Source::Indexed(Box::new(index))));
    }
    let records = crate::dependency_index::recording::events(source)?;
    SequenceCatalog::try_prepare(records).map(|catalog| Some(Source::Inline(catalog)))
}
