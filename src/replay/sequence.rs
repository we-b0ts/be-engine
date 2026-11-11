//! Prepare immutable event postings once, outside Target request execution.
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::time::{Duration, Instant};
use traffic_model::trace::{CaptureEvent, RecordedEvent};
use traffic_replay::SequenceCatalog;
use traffic_replay::{EventKind, SequenceClaim, SequenceRuntime};

pub(super) struct RequestWait {
    scopes: Vec<ScopeWait>,
    pending: Option<traffic_replay::PendingRequest>,
    bytes: usize,
}

struct ScopeWait {
    runtime: Arc<SequenceRuntime>,
    changed: tokio::sync::watch::Receiver<u64>,
    case: bool,
    missing: Option<(u64, Instant)>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct MissingDependency {
    pub case_id: Option<String>,
    pub expected: traffic_replay::SourceEvent,
    pub ownership_revision: u64,
    pub attribution_review: &'static str,
}

impl RequestWait {
    pub(super) fn failed(&self) -> bool {
        self.scopes.iter().any(|scope| scope.runtime.failed())
    }
    pub(super) fn new(state: &super::ReplayState, bytes: usize) -> Option<Self> {
        let scopes: Vec<_> =
            state
                .active_sequence
                .clone()
                .map(|runtime| (true, runtime))
                .into_iter()
                .chain(
                    state.run_sequence.as_ref().into_iter().flat_map(|run| {
                        run.runtimes.iter().cloned().map(|runtime| (false, runtime))
                    }),
                )
                .map(|(case, runtime)| ScopeWait {
                    changed: runtime.subscribe_requests(),
                    runtime,
                    case,
                    missing: None,
                })
                .collect();
        (!scopes.is_empty()).then_some(Self {
            scopes,
            pending: None,
            bytes,
        })
    }

    pub(super) fn reserve(&mut self) -> Result<()> {
        if self.pending.is_none() {
            self.pending = Some(self.scopes[0].runtime.pending(self.bytes)?);
        }
        Ok(())
    }

    pub(super) fn deadline(&mut self, overall: Instant) -> Option<Instant> {
        let mut deadline = None;
        for scope in &mut self.scopes {
            if scope.runtime.failed() {
                return None;
            }
            let Some(expected) = scope.runtime.expected() else {
                continue;
            };
            let until = if expected.kind == EventKind::Request {
                if scope
                    .missing
                    .as_ref()
                    .is_none_or(|(sequence, _)| *sequence != expected.sequence)
                {
                    scope.missing = Some((
                        expected.sequence,
                        Instant::now() + Duration::from_millis(250),
                    ));
                }
                scope
                    .missing
                    .expect("missing request deadline")
                    .1
                    .min(overall)
            } else {
                overall
            };
            deadline = Some(deadline.map_or(until, |before: Instant| before.min(until)));
        }
        deadline
    }

    pub(super) async fn wait(&mut self, deadline: Instant) -> bool {
        use futures_util::{StreamExt, stream::FuturesUnordered};
        let mut changed: FuturesUnordered<_> = self
            .scopes
            .iter_mut()
            .map(|scope| scope.changed.changed())
            .collect();
        matches!(
            tokio::time::timeout_at(deadline, changed.next()).await,
            Ok(Some(Ok(())))
        )
    }

    pub(super) fn diagnose(&self, revision: u64, case: Option<&str>) -> Vec<MissingDependency> {
        self.scopes
            .iter()
            .filter_map(|scope| {
                Some(MissingDependency {
                    case_id: scope.case.then_some(case).flatten().map(str::to_owned),
                    expected: scope.runtime.missing_request(revision)?,
                    ownership_revision: revision,
                    attribution_review: "required",
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct Binding {
    runtime: Option<Arc<SequenceRuntime>>,
    dependencies: HashMap<usize, u64>,
    positions: HashMap<u64, usize>,
    run: Option<Box<Binding>>,
    runtimes: Vec<Arc<SequenceRuntime>>,
    owners: HashMap<usize, Arc<SequenceRuntime>>,
}

impl Binding {
    pub(super) fn new(
        runtime: Arc<SequenceRuntime>,
        references: impl Iterator<Item = (usize, u64)>,
    ) -> Self {
        let dependencies: HashMap<_, _> = references.collect();
        let positions = dependencies
            .iter()
            .map(|(index, dependency)| (*dependency, *index))
            .collect();
        Self {
            runtime: Some(runtime.clone()),
            dependencies,
            positions,
            run: None,
            runtimes: vec![runtime],
            owners: HashMap::new(),
        }
    }

    /// The outer Option distinguishes a prepared strict trace from low-level
    /// unscoped native fixtures. Only the current Source slot is visited.
    pub(super) fn expected_index(&self) -> Option<Option<usize>> {
        let runtime = self.runtime.as_ref()?;
        Some(
            runtime
                .expected()
                .filter(|event| event.kind == EventKind::Request)
                .and_then(|event| self.positions.get(&event.dependency_sequence).copied()),
        )
    }

    fn merge(bindings: Vec<Self>) -> Self {
        let mut combined = Self::default();
        for binding in bindings {
            for index in binding.dependencies.keys() {
                combined.owners.insert(
                    *index,
                    binding.runtime.as_ref().expect("scope runtime").clone(),
                );
            }
            combined.dependencies.extend(binding.dependencies);
            combined.positions.extend(binding.positions);
            combined.runtimes.extend(binding.runtimes);
        }
        combined
    }

    pub(super) fn expected_in(&self, source: super::ReplaySource) -> Option<Arc<[usize]>> {
        if source == super::ReplaySource::Case {
            self.expected_index()
                .map(|index| index.into_iter().collect::<Vec<_>>().into())
        } else {
            let run = self.run.as_ref()?;
            Some(
                run.runtimes
                    .iter()
                    .filter_map(|runtime| {
                        let event = runtime.expected()?;
                        (event.kind == EventKind::Request)
                            .then(|| run.positions.get(&event.dependency_sequence).copied())
                            .flatten()
                    })
                    .collect::<Vec<_>>()
                    .into(),
            )
        }
    }

    fn attach_run(&mut self, run: Binding) {
        self.run = Some(Box::new(run));
    }

    pub(super) fn claim(&self, index: usize) -> Result<Option<SequenceClaim>> {
        let Some(dependency) = self.dependencies.get(&index) else {
            return self.run.as_ref().map_or(Ok(None), |run| run.claim(index));
        };
        self.owners
            .get(&index)
            .or(self.runtime.as_ref())
            .context("sequence binding has no runtime")?
            .admit(*dependency)
            .map(Some)
    }
}

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
            runtime,
            plan.native
                .mysql
                .iter()
                .filter_map(|index| Some((*index, self.mysql.recorded_sequence(*index)?))),
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
