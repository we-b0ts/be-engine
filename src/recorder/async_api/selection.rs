//! Ordered lifecycle selection retains each candidate's early resource signals.
use super::*;
use anyhow::Result;
use hyper::{Method, Uri};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(crate) struct AsyncScope {
    pub(crate) api: String,
    runtime: Arc<Runtime>,
}

#[cfg(test)]
mod tests;

#[derive(Debug)]
struct Runtime {
    candidates: Vec<(usize, ResourceScope)>,
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
    pub(crate) fn for_primary(
        rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> Option<Self> {
        let body = crate::json_value::parse_with_limit(body, body.len());
        rules.iter().find_map(|(api, rules)| {
            let candidates = rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| {
                    crate::policy::async_api_matches(
                        api,
                        rule,
                        method.as_str(),
                        &uri.to_string(),
                        body.as_ref(),
                    )
                })
                .map(|(index, rule)| (index, ResourceScope::new(rule.clone())))
                .collect::<Vec<_>>();
            let (_, first) = candidates.first()?;
            let decided =
                first.rule.when_response.is_empty() && first.rule.unless_response.is_empty();
            let signals = vec![None; candidates.len()];
            let signal_generations = vec![None; candidates.len()];
            let observed_matches = vec![BTreeSet::new(); candidates.len()];
            Some(Self {
                api: api.clone(),
                runtime: Arc::new(Runtime {
                    candidates,
                    selection: Mutex::new(Selection {
                        decided,
                        selected: decided.then_some(0),
                        signals,
                        signal_generations,
                        observed_matches,
                    }),
                }),
            })
        })
    }

    /// Only Source's captured primary body selects a scenario; Target output
    /// never supplies lifecycle authority. Missing JSON cannot satisfy a field.
    pub(crate) fn select_response(&self, body: Option<&Value>) -> (bool, Option<AsyncSignal>) {
        let mut state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        if !state.decided {
            state.selected =
                self.runtime.candidates.iter().position(|(_, scope)| {
                    crate::policy::async_response_matches(&scope.rule, body)
                });
            state.decided = true;
        }
        (
            state.selected.is_some(),
            state
                .selected
                .and_then(|index| state.signals[index].clone()),
        )
    }

    pub(crate) fn scenario_index(&self) -> Option<usize> {
        let state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        state.selected.map(|index| self.runtime.candidates[index].0)
    }

    pub(crate) fn all_ends_matched(&self) -> bool {
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

    #[cfg(test)]
    pub(crate) fn observe(&self, event: &RecorderEvent) -> Option<AsyncSignal> {
        self.observe_at(event, 0)
    }

    /// Return only this exchange's new match. Retained early signals are used
    /// by response selection, never replayed for an unrelated later exchange.
    pub(crate) fn observe_at(&self, event: &RecorderEvent, generation: u64) -> Option<AsyncSignal> {
        let mut state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        let identity = match event {
            RecorderEvent::RedisExchange(event) => Some(event.id),
            RecorderEvent::MysqlExchange(event) => Some(event.id),
            RecorderEvent::HttpExchange(event) => Some(event.id),
            _ => None,
        };
        let mut selected_signal = None;
        let redis = redis_event::Event::from_event(event);
        let actual_sql = OnceCell::new();
        for (index, (_, candidate)) in self.runtime.candidates.iter().enumerate() {
            if state.decided && state.selected != Some(index)
                || state.signals[index]
                    .as_ref()
                    .is_some_and(|signal| signal.end_reason != AsyncEndReason::Resource)
                || identity.is_some_and(|id| state.observed_matches[index].contains(&id))
            {
                continue;
            }
            let Some(signal) = candidate.observe_cached(event, redis.as_ref(), &actual_sql) else {
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

    pub(crate) fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>> {
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
