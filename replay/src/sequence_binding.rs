//! Native inventory positions bound to protocol-independent event schedules.
use crate::{PublishedMessageBatch, SequenceClaim, SequenceRuntime};
use anyhow::{Context, Result};
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, Default)]
pub struct SequenceBinding {
    runtime: Option<Arc<SequenceRuntime>>,
    dependencies: HashMap<usize, u64>,
    positions: HashMap<u64, usize>,
    run: Option<Box<SequenceBinding>>,
    runtimes: Vec<Arc<SequenceRuntime>>,
    owners: HashMap<usize, Arc<SequenceRuntime>>,
}

impl SequenceBinding {
    pub fn new(
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
    pub fn expected_index(&self) -> Option<Option<usize>> {
        let runtime = self.runtime.as_ref()?;
        Some(
            runtime
                .admissible_request()
                .and_then(|event| self.positions.get(&event.dependency_sequence).copied()),
        )
    }

    pub fn merge(bindings: Vec<Self>) -> Self {
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

    pub fn expected_in(&self, source: crate::ReplaySource) -> Option<Arc<[usize]>> {
        if source == crate::ReplaySource::Case {
            self.expected_index()
                .map(|index| index.into_iter().collect::<Vec<_>>().into())
        } else {
            let run = self.run.as_ref()?;
            Some(
                run.runtimes
                    .iter()
                    .filter_map(|runtime| {
                        let event = runtime.admissible_request()?;
                        run.positions.get(&event.dependency_sequence).copied()
                    })
                    .collect::<Vec<_>>()
                    .into(),
            )
        }
    }

    pub fn expected_messages(&self, source: crate::ReplaySource) -> Option<Vec<usize>> {
        self.expected_message_indices(source).map(Iterator::collect)
    }

    pub(crate) fn expected_message_indices(
        &self,
        source: crate::ReplaySource,
    ) -> Option<impl Iterator<Item = usize> + '_> {
        let (binding, runtimes) = if source == crate::ReplaySource::Case {
            (self, std::slice::from_ref(self.runtime.as_ref()?))
        } else {
            let run = self.run.as_deref()?;
            (run, run.runtimes.as_slice())
        };
        Some(runtimes.iter().filter_map(move |runtime| {
            let event = runtime.admissible_message()?;
            binding.positions.get(&event.dependency_sequence).copied()
        }))
    }

    pub(crate) fn session_position(&self, dependency: u64) -> Option<usize> {
        self.session_run()?.0.positions.get(&dependency).copied()
    }

    pub(crate) fn matches_message_batch(&self, batch: &PublishedMessageBatch) -> bool {
        self.session_run()
            .is_some_and(|(_, runtime)| batch.belongs_to(runtime))
    }

    fn session_run(&self) -> Option<(&Self, &SequenceRuntime)> {
        let run = self.run.as_deref()?;
        let [runtime] = run.runtimes.as_slice() else {
            return None;
        };
        runtime
            .is_session_trace()
            .then_some((run, runtime.as_ref()))
    }

    pub fn subscriptions(&self) -> Vec<tokio::sync::watch::Receiver<u64>> {
        self.runtimes
            .iter()
            .map(|runtime| runtime.subscribe())
            .chain(
                self.run
                    .iter()
                    .flat_map(|run| run.runtimes.iter().map(|runtime| runtime.subscribe())),
            )
            .collect()
    }

    pub fn attach_run(&mut self, run: SequenceBinding) {
        self.run = Some(Box::new(run));
    }

    pub(crate) fn is_session_trace(&self) -> bool {
        self.run.as_ref().is_some_and(|run| {
            run.runtimes
                .iter()
                .any(|runtime| runtime.is_session_trace())
        })
    }

    pub fn claim(&self, index: usize) -> Result<Option<SequenceClaim>> {
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
