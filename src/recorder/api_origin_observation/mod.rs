//! Select activity for one primary API without changing dependency ownership.
//!
//! This scope observes only configured API-origin selectors. Missing or ambiguous
//! INSERT capture permits an explicitly reported selector-only activity scope;
//! it never supplies identity proof for recording attribution or Replay.
mod request;
#[cfg(test)]
mod tests;
mod transaction;

use std::sync::{Arc, Mutex};

use hyper::{Method, Uri};
use serde::Serialize;
use uuid::Uuid;

use crate::config::{ApiTriggerSource, BackgroundDependencyRuleConfig};
use crate::recorder::{MysqlExchangeEvent, RecorderEvent};

pub(crate) use request::DependencyRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelectionScope {
    BoundIdentity,
    SelectorOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureState {
    Missing,
    Bound,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OriginRuleSnapshot {
    pub(crate) rule_name: String,
    pub(crate) capture_state: CaptureState,
    pub(crate) selected_bound: u64,
    pub(crate) selected_selector_only: u64,
}

#[derive(Clone)]
pub(crate) struct ApiOriginScope {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for ApiOriginScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Captured identities and dependency payloads are private live facts.
        formatter
            .debug_struct("ApiOriginScope")
            .field("rules", &self.snapshot())
            .finish()
    }
}

struct State {
    origins: Vec<Origin>,
    rules: Vec<Rule>,
    transactions: transaction::Transactions,
}

struct Origin {
    source: ApiTriggerSource,
    capture: Capture,
}

#[derive(Default)]
enum Capture {
    #[default]
    Missing,
    Bound {
        identity: String,
        exchange: Uuid,
    },
    Ambiguous,
}

struct Rule {
    config: BackgroundDependencyRuleConfig,
    origin: usize,
    selected_bound: u64,
    selected_selector_only: u64,
}

impl ApiOriginScope {
    pub(crate) fn for_primary(
        rules: &[BackgroundDependencyRuleConfig],
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> Option<Self> {
        let eligible: Vec<_> = rules
            .iter()
            .filter(|rule| {
                rule.trigger_source().is_some_and(|source| {
                    source.method == method.as_str() && source.path == uri.path()
                })
            })
            .collect();
        if eligible.is_empty() {
            return None;
        }
        let json = eligible
            .iter()
            .any(|rule| !rule.trigger_source().unwrap().request_body_json.is_empty())
            .then(|| crate::json_value::parse_with_limit(body, body.len()))
            .flatten();
        let mut state = State {
            origins: Vec::new(),
            rules: Vec::new(),
            transactions: transaction::Transactions::default(),
        };
        for rule in eligible {
            let source = rule.trigger_source().expect("API-origin rule");
            if !source.request_body_json.iter().all(|(pointer, expected)| {
                json.as_ref().and_then(|body| body.pointer(pointer)) == Some(expected)
            }) {
                continue;
            }
            let origin = state
                .origins
                .iter()
                .position(|origin| origin.source == *source)
                .unwrap_or_else(|| {
                    state.origins.push(Origin {
                        source: source.clone(),
                        capture: Capture::Missing,
                    });
                    state.origins.len() - 1
                });
            state.rules.push(Rule {
                config: rule.clone(),
                origin,
                selected_bound: 0,
                selected_selector_only: 0,
            });
        }
        (!state.rules.is_empty()).then(|| Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Select a semantic request at admission. Reservation clones and writer
    /// completion do not call this method and cannot extend business activity.
    pub(crate) fn select_request(&self, request: &DependencyRequest<'_>) -> Option<SelectionScope> {
        let mut state = self.state.lock().expect("API-origin scope poisoned");
        let mut selected = state.direct_matches(request);
        let State {
            rules,
            origins,
            transactions,
        } = &mut *state;
        transactions.select(request, rules, origins, &mut selected);
        let mut scope = None;
        for (index, selection) in selected {
            let rule = &mut rules[index];
            match selection {
                SelectionScope::BoundIdentity => {
                    rule.selected_bound = rule.selected_bound.saturating_add(1);
                    scope = Some(SelectionScope::BoundIdentity);
                }
                SelectionScope::SelectorOnly => {
                    rule.selected_selector_only = rule.selected_selector_only.saturating_add(1);
                    scope.get_or_insert(SelectionScope::SelectorOnly);
                }
            }
        }
        scope
    }

    /// Call only for completed exchanges retaining this primary case's original
    /// request reservation. An unrelated current-case snapshot is not evidence.
    pub(crate) fn observe_completed(&self, event: &RecorderEvent) {
        let RecorderEvent::MysqlExchange(exchange) = event else {
            return;
        };
        let mut state = self.state.lock().expect("API-origin scope poisoned");
        state.capture(exchange);
        let State {
            rules,
            origins,
            transactions,
        } = &mut *state;
        transactions.observe(exchange, rules, origins);
    }

    pub(crate) fn snapshot(&self) -> Vec<OriginRuleSnapshot> {
        let state = self.state.lock().expect("API-origin scope poisoned");
        state
            .rules
            .iter()
            .map(|rule| OriginRuleSnapshot {
                rule_name: rule.config.name().into(),
                capture_state: match state.origins[rule.origin].capture {
                    Capture::Missing => CaptureState::Missing,
                    Capture::Bound { .. } => CaptureState::Bound,
                    Capture::Ambiguous => CaptureState::Ambiguous,
                },
                selected_bound: rule.selected_bound,
                selected_selector_only: rule.selected_selector_only,
            })
            .collect()
    }
}

impl State {
    fn direct_matches(
        &self,
        request: &DependencyRequest<'_>,
    ) -> std::collections::BTreeMap<usize, SelectionScope> {
        self.rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                let identity = request::identity(&rule.config, request)?;
                self.origins[rule.origin]
                    .capture
                    .selection(&identity)
                    .map(|scope| (index, scope))
            })
            .collect()
    }

    fn capture(&mut self, exchange: &MysqlExchangeEvent) {
        if exchange.command != "COM_QUERY"
            || exchange.outcome != crate::DependencyExchangeOutcome::Response
            || exchange.response.status != "ok"
            || exchange.response.affected_rows != Some(1)
            || !exchange.parse_warnings.is_empty()
        {
            return;
        }
        let value = request::capture_value(exchange);
        for origin in &mut self.origins {
            let Some(identity) =
                crate::api_trigger::capture_identity(origin.source.binding().1, &value)
            else {
                continue;
            };
            origin.capture = match &origin.capture {
                Capture::Missing => Capture::Bound {
                    identity,
                    exchange: exchange.id,
                },
                Capture::Bound {
                    exchange: id,
                    identity: previous,
                } if *id == exchange.id && *previous == identity => continue,
                _ => Capture::Ambiguous,
            };
        }
    }
}

impl Capture {
    fn selection(&self, identity: &str) -> Option<SelectionScope> {
        match self {
            Self::Bound {
                identity: captured, ..
            } if identity != captured => None,
            Self::Bound { .. } => Some(SelectionScope::BoundIdentity),
            Self::Missing | Self::Ambiguous => Some(SelectionScope::SelectorOnly),
        }
    }
}
