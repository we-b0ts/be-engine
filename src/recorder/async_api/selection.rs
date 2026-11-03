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
                .map(|(index, rule)| {
                    (
                        index,
                        ResourceScope {
                            rule: rule.clone(),
                            progress: Default::default(),
                        },
                    )
                })
                .collect::<Vec<_>>();
            let (_, first) = candidates.first()?;
            let decided =
                first.rule.when_response.is_empty() && first.rule.unless_response.is_empty();
            let signals = vec![None; candidates.len()];
            Some(Self {
                api: api.clone(),
                runtime: Arc::new(Runtime {
                    candidates,
                    selection: Mutex::new(Selection {
                        decided,
                        selected: decided.then_some(0),
                        signals,
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

    pub(crate) fn observe(&self, event: &RecorderEvent) -> Option<AsyncSignal> {
        let mut state = self
            .runtime
            .selection
            .lock()
            .expect("async scenario selection poisoned");
        for (index, (_, candidate)) in self.runtime.candidates.iter().enumerate() {
            if (!state.decided || state.selected == Some(index)) && state.signals[index].is_none() {
                state.signals[index] = candidate.observe(event);
            }
        }
        state
            .selected
            .and_then(|index| state.signals[index].clone())
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
