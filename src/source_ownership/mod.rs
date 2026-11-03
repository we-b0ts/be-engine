//! Pure Source-only positive ownership; capture, publication and delivery stay separate.
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

mod mysql;
mod origins;
mod projection;
mod redis;
mod transactions;
pub(crate) use projection::request_unavailable;
pub(crate) use projection::request_view;

#[derive(Debug, Clone)]
pub(crate) struct CaseFacts {
    pub case_id: Uuid,
    pub method: String,
    pub uri: String,
    pub request: Option<Value>,
    pub request_unavailable: bool,
    pub response: Option<Value>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Assignment {
    pub case_id: Uuid,
    pub rule_id: String,
    pub rule_fingerprint: String,
    pub scenario_index: usize,
    pub origin_exchange_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Problem {
    pub exchange_id: Option<Uuid>,
    pub case_id: Option<Uuid>,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub decisions: BTreeMap<Uuid, Assignment>,
    pub unresolved: BTreeSet<Uuid>,
    pub problems: Vec<Problem>,
}

pub(crate) fn classify(
    rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    inputs: &[CaseFacts],
    events: &[Value],
) -> Result<Outcome> {
    classify_inner(rules, inputs, events)
}

/// Conservative negative scope if execution is unavailable. No origin is affirmed.
/// The caller may preserve existing independently proved manual decisions.
pub(crate) fn potential_occurrences(
    rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    events: &[Value],
) -> BTreeSet<Uuid> {
    let requests = rules
        .values()
        .flat_map(|rules| rules.iter())
        .filter_map(|rule| rule.ownership.as_ref())
        .flat_map(|ownership| &ownership.requests)
        .collect::<Vec<_>>();
    let mut result = BTreeSet::new();
    for event in events {
        if !candidate_scope(event) {
            continue;
        }
        for request in &requests {
            if mysql::selector(request, event).is_some()
                || redis::selector(request, event).is_some()
            {
                if let Some(id) = event_id(event) {
                    result.insert(id);
                }
                if let Some(prelude) = redis::prelude(request, event, events)
                    && candidate_scope(prelude)
                    && let Some(id) = event_id(prelude)
                {
                    result.insert(id);
                }
            }
        }
    }
    result.extend(transactions::potential(events, &result));
    result
}

pub(super) struct Rule<'a> {
    api: &'a str,
    scenario_index: usize,
    ownership: &'a crate::policy::AsyncOwnership,
    fingerprint: String,
}

pub(super) struct Prepared<'a> {
    rules: &'a [Rule<'a>],
    sql: mysql::prepared::Matches<'a>,
}

fn classify_inner(
    rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
    inputs: &[CaseFacts],
    events: &[Value],
) -> Result<Outcome> {
    ensure!(
        inputs.len() <= 100_000 && events.len() <= 2_000_000,
        "async ownership Source inventory exceeds bounds"
    );
    let mut outcome = Outcome::default();
    let mut selected = Vec::new();
    for (api, scenarios) in rules {
        for (scenario_index, scenario) in scenarios.iter().enumerate() {
            if let Some(ownership) = &scenario.ownership {
                crate::policy::validate_async_ownership(ownership)?;
                selected.push(Rule {
                    api,
                    scenario_index,
                    ownership,
                    fingerprint: crate::policy::async_rules_fingerprint(scenarios),
                });
            }
        }
    }
    let prepared = Prepared {
        rules: &selected,
        sql: mysql::prepared::Matches::new(&selected, events),
    };
    let wires = transactions::Wires::new(events);
    let origins = origins::collect(&prepared, rules, inputs, events, &wires, &mut outcome)?;
    let mut conflicts = BTreeSet::new();
    for event in events {
        if event["event_type"] != "redis_exchange" {
            continue;
        }
        let candidates = redis::candidates(&selected, &origins, inputs, event, &mut outcome);
        if let Some((origin, request)) = unique(candidates, event, &mut outcome) {
            assign(&mut outcome, &mut conflicts, event, &origin.assignment);
            if let Some(prelude) = redis::prelude(request, event, events)
                && candidate_scope(prelude)
            {
                if admissible(origin, inputs, prelude, &origin.bindings)
                    && event_id(event).is_some_and(|id| outcome.decisions.contains_key(&id))
                {
                    assign(&mut outcome, &mut conflicts, prelude, &origin.assignment);
                } else {
                    problem(
                        &mut outcome,
                        prelude,
                        Some(origin),
                        "unproven_script_prelude_ownership",
                    );
                }
            }
        }
    }
    transactions::classify(
        &prepared,
        &origins,
        inputs,
        events,
        &wires,
        &mut outcome,
        &mut conflicts,
    );
    for event in events {
        if !event_id(event).is_some_and(|id| outcome.unresolved.contains(&id)) {
            continue;
        }
        for rule in &selected {
            for request in &rule.ownership.requests {
                if redis::selector(request, event).is_some()
                    && let Some(prelude) = redis::prelude(request, event, events)
                    && candidate_scope(prelude)
                {
                    problem(
                        &mut outcome,
                        prelude,
                        None,
                        "unproven_script_invocation_ownership",
                    );
                }
            }
        }
    }
    Ok(outcome)
}

fn unique<'a, T>(
    candidates: Vec<(&'a origins::Origin, T)>,
    event: &Value,
    outcome: &mut Outcome,
) -> Option<(&'a origins::Origin, T)> {
    let owners = candidates
        .iter()
        .map(|(origin, _)| origin.assignment.case_id)
        .collect::<BTreeSet<_>>();
    if owners.len() != 1 {
        if owners.len() > 1 {
            problem(outcome, event, None, "ambiguous_origin");
        }
        return None;
    }
    candidates.into_iter().next()
}

fn event_id(event: &Value) -> Option<Uuid> {
    serde_json::from_value(event["capture"]["exchange_id"].clone()).ok()
}
fn epoch(event: &Value) -> Option<Uuid> {
    serde_json::from_value(event["capture"]["process_epoch"].clone()).ok()
}
fn started(event: &Value) -> Option<DateTime<Utc>> {
    serde_json::from_value(event["capture"]["started_at"].clone()).ok()
}

fn problem(outcome: &mut Outcome, event: &Value, origin: Option<&origins::Origin>, reason: &str) {
    if candidate_scope(event)
        && let Some(id) = event_id(event)
    {
        outcome.unresolved.insert(id);
        outcome.decisions.remove(&id);
    }
    if outcome.problems.len() < 256 {
        outcome.problems.push(Problem {
            exchange_id: event_id(event),
            case_id: origin.map(|origin| origin.assignment.case_id),
            rule_id: origin
                .map(|origin| origin.assignment.rule_id.clone())
                .unwrap_or_default(),
            reason: reason.into(),
        });
    }
}

fn assign(
    outcome: &mut Outcome,
    conflicts: &mut BTreeSet<Uuid>,
    event: &Value,
    assignment: &Assignment,
) {
    if !candidate_scope(event) {
        return;
    }
    let Some(id) = event_id(event) else {
        return;
    };
    if conflicts.contains(&id) || outcome.unresolved.contains(&id) {
        return;
    }
    if outcome
        .decisions
        .get(&id)
        .is_some_and(|previous| previous.case_id != assignment.case_id)
    {
        outcome.decisions.remove(&id);
        conflicts.insert(id);
        problem(outcome, event, None, "conflicting_ownership_rules");
    } else {
        outcome
            .decisions
            .entry(id)
            .or_insert_with(|| assignment.clone());
    }
}

fn admissible(
    origin: &origins::Origin,
    inputs: &[CaseFacts],
    event: &Value,
    bindings: &BTreeMap<String, u64>,
) -> bool {
    if !candidate_scope(event)
        || !projection::native_identity(event)
        || epoch(event) != Some(origin.epoch)
        || started(event).is_none_or(|time| time < origin.started_at)
        || bindings.is_empty()
        || !bindings
            .iter()
            .all(|(name, value)| origin.bindings.get(name) == Some(value))
    {
        return false;
    }
    let captured = event["capture"]["admitted_case"]
        .as_str()
        .or_else(|| event["capture"]["attribution"]["origin_case_id"].as_str())
        .and_then(|id| Uuid::parse_str(id).ok());
    if captured == Some(origin.assignment.case_id) {
        return true;
    }
    if captured.is_some_and(|case| !inputs.iter().any(|input| input.case_id == case)) {
        return false;
    }
    !inputs
        .iter()
        .filter(|input| {
            input.case_id != origin.assignment.case_id
                && input.started_at >= origin.input_started_at
                && started(event).is_some_and(|time| input.started_at <= time)
        })
        .any(|input| {
            bindings
                .values()
                .any(|value| origins::references(input, *value))
        })
}

/// Both affirmative and negative policy decisions share the same business scope.
/// Physical native observations outside it remain available for continuity proof.
pub(crate) fn candidate_scope(event: &Value) -> bool {
    event["capture"]["phase"] == "runtime"
        && event["capture"]["semantic_required"] == true
        && matches!(
            event["capture"]["attribution"]["kind"].as_str(),
            Some("case" | "unattributed")
        )
}

#[cfg(test)]
mod tests;
