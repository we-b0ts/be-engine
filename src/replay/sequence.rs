//! Prepare immutable event postings once, outside Target request execution.
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use traffic_model::trace::{CaptureEvent, RecordedEvent};
use traffic_replay::SequenceCatalog;
use traffic_replay::SequenceRuntime;

pub(super) use traffic_replay::request_wait::MissingDependency;

impl traffic_replay::request::ExecutionState for super::ReplayState {
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

pub(super) use traffic_replay::SequenceBinding as Binding;

impl super::ReplayState {
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
        self.http_sequence_claims.retain(|_, claim| {
            self.run_sequence
                .as_ref()
                .is_some_and(|run| run.runtimes.iter().any(|runtime| claim.belongs_to(runtime)))
        });
        self.http_sequence = Binding::default();
        self.redis.lifecycle.sequence = Binding::default();
        self.mysql.lifecycle.sequence = Binding::default();
        self.native.core.lifecycle.sequence = Binding::default();
        let Some(runtime) = self.active_sequence.clone() else {
            self.attach_run_sequence();
            return;
        };
        let plan = &self.case_execution_plans[case.expect("prepared Case sequence")];
        self.http_sequence = Binding::new(
            runtime.clone(),
            plan.native.http.iter().filter_map(|index| {
                Some((
                    *index,
                    self.http_exchanges.get(*index)?.recorded_sequence()?,
                ))
            }),
        );
        self.redis.lifecycle.sequence = Binding::new(
            runtime.clone(),
            plan.native
                .redis
                .iter()
                .filter_map(|index| Some((*index, self.redis.recorded_sequence(*index)?))),
        );
        self.mysql.lifecycle.sequence = Binding::new(
            runtime.clone(),
            plan.native
                .mysql
                .iter()
                .filter_map(|index| Some((*index, self.mysql.recorded_sequence(*index)?))),
        );
        self.native.core.lifecycle.sequence = Binding::new(
            runtime,
            plan.native
                .registered
                .iter()
                .filter_map(|index| Some((*index, self.native.recorded_sequence(*index)?))),
        );
        self.attach_run_sequence();
    }
}

mod run;
pub(super) use run::RunBindings;

pub(super) fn load(source: &Path) -> Result<Option<Arc<SequenceCatalog>>> {
    let Some(root) = crate::dependency_index::recording::root(source) else {
        return Ok(None);
    };
    let input = std::fs::File::open(root.join("dependency-lifecycle.jsonl"))
        .context("recording has no ordered dependency event journal")?;
    let records = BufReader::new(input)
        .lines()
        .map(|line| -> Result<RecordedEvent<CaptureEvent>> { Ok(serde_json::from_str(&line?)?) });
    SequenceCatalog::try_prepare(records).map(Some)
}
