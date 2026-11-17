//! Ordered selection and independent retention of early completion signals.
use super::*;
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct AsyncScope {
    pub(crate) api: String,
    runtime: Arc<Runtime>,
}

#[derive(Debug)]
struct Runtime {
    candidates: Vec<(usize, Arc<dyn CompletionRule>)>,
    selection: Mutex<Selection>,
}

#[derive(Debug)]
struct Selection {
    decided: bool,
    selected: Option<usize>,
    signals: Vec<Option<AsyncSignal>>,
    signal_generations: Vec<Option<u64>>,
    observed_matches: Vec<BTreeSet<uuid::Uuid>>,
}

impl AsyncScope {
    pub(crate) fn new(
        api: String,
        candidates: Vec<(usize, Arc<dyn CompletionRule>)>,
    ) -> Option<Self> {
        let (_, first) = candidates.first()?;
        let decided = !first.requires_response_selection();
        let count = candidates.len();
        Some(Self {
            api,
            runtime: Arc::new(Runtime {
                candidates,
                selection: Mutex::new(Selection {
                    decided,
                    selected: decided.then_some(0),
                    signals: vec![None; count],
                    signal_generations: vec![None; count],
                    observed_matches: vec![BTreeSet::new(); count],
                }),
            }),
        })
    }

    /// Only Source's captured primary body selects a scenario; Target output
    /// never supplies lifecycle authority. Missing JSON cannot satisfy a field.
    pub fn select_response(&self, body: Option<&Value>) -> (bool, Option<AsyncSignal>) {
        let mut state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        if !state.decided {
            state.selected = self
                .runtime
                .candidates
                .iter()
                .position(|(_, scope)| scope.response_matches(body));
            state.decided = true;
        }
        (
            state.selected.is_some(),
            state
                .selected
                .and_then(|index| state.signals[index].clone()),
        )
    }

    pub fn scenario_index(&self) -> Option<usize> {
        let state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        state.selected.map(|index| self.runtime.candidates[index].0)
    }

    pub fn all_ends_matched(&self) -> bool {
        let state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        state
            .selected
            .is_some_and(|index| self.runtime.candidates[index].1.all_ends_matched())
    }

    pub(crate) fn selected_signal_generation(&self) -> Option<u64> {
        let state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        state
            .selected
            .and_then(|index| state.signal_generations[index])
    }

    /// Return only this exchange's new match. Retained early signals are used
    /// by response selection, never replayed for an unrelated later exchange.
    pub(crate) fn observe_at(
        &self,
        event: &dyn CompletionEvent,
        generation: u64,
    ) -> Option<AsyncSignal> {
        let mut state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        let identity = event.identity();
        let mut selected_signal = None;
        for (index, (_, candidate)) in self.runtime.candidates.iter().enumerate() {
            if state.decided && state.selected != Some(index)
                || state.signals[index]
                    .as_ref()
                    .is_some_and(|signal| signal.end_reason != AsyncEndReason::Resource)
                || identity.is_some_and(|id| state.observed_matches[index].contains(&id))
            {
                continue;
            }
            let Some(signal) = event.evaluate(candidate.as_ref()) else {
                continue;
            };
            if signal.end_reason == AsyncEndReason::Resource {
                let Some(identity) = identity else {
                    continue;
                };
                if state.observed_matches[index].len() >= MAX_OCCURRENCE_OBSERVATIONS {
                    continue;
                }
                state.observed_matches[index].insert(identity);
            }
            state.signals[index] = Some(signal.clone());
            state.signal_generations[index] = Some(generation);
            if state.selected == Some(index) {
                selected_signal = Some(signal);
            }
        }
        selected_signal
    }

    pub fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>> {
        let state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        match state.selected {
            Some(index) => self.runtime.candidates[index].1.observe_recorded(event),
            None => Ok(None),
        }
    }
}
