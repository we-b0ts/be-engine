use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::result::{E2eValueObservation, response_observation};
use super::{E2eRunContext, config, model, store, support};

const MAX_DISTINCT_SOURCE_VALUES: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eSourceValueCount {
    pub observation: E2eValueObservation,
    pub cases: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eSourceVariation {
    pub pointer_scope: &'static str,
    pub pointer: String,
    pub observed_cases: usize,
    pub distinct_values: Vec<E2eSourceValueCount>,
    pub omitted_distinct_values: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDependencyCorrelation {
    pub cases: usize,
    pub matrix: BTreeMap<String, usize>,
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eDirtyCounts {
    pub complete: bool,
    pub dirty: bool,
    pub event_counts: Value,
}

pub fn query_e2e_source_variation(
    context: E2eRunContext,
    api: &str,
    pointer: &str,
) -> Result<E2eSourceVariation> {
    let state = finalized_focused_state(context, api)?;
    let mut values = BTreeMap::<String, (E2eValueObservation, usize)>::new();
    for case in &state.cases {
        let Some(assertion) = &case.response_assertion else {
            continue;
        };
        let observation = response_observation(&assertion.expected_response, pointer);
        let key = serde_json::to_string(&observation)?;
        let entry = values.entry(key).or_insert((observation, 0));
        entry.1 += 1;
    }
    let observed_cases = values.values().map(|(_, cases)| *cases).sum();
    let omitted_distinct_values = values.len().saturating_sub(MAX_DISTINCT_SOURCE_VALUES);
    let distinct_values = values
        .into_values()
        .take(MAX_DISTINCT_SOURCE_VALUES)
        .map(|(observation, cases)| E2eSourceValueCount { observation, cases })
        .collect();
    Ok(E2eSourceVariation {
        pointer_scope: "decoded_response_body_json",
        pointer: pointer.to_string(),
        observed_cases,
        distinct_values,
        omitted_distinct_values,
    })
}

pub fn query_e2e_dependency_correlation(
    context: E2eRunContext,
    api: &str,
) -> Result<E2eDependencyCorrelation> {
    let state = finalized_focused_state(context, api)?;
    let mut matrix = BTreeMap::new();
    for case in &state.cases {
        let response = match case.assertion_passed {
            Some(true) => "response_passed",
            Some(false) => "response_nonpassing",
            None => "response_incomplete",
        };
        let dependency = match case.replay_clean {
            Some(true) => "dependency_clean",
            Some(false) => "dependency_dirty",
            None => "dependency_unknown",
        };
        *matrix
            .entry(format!("{response}__{dependency}"))
            .or_default() += 1;
    }
    Ok(E2eDependencyCorrelation {
        cases: state.cases.len(),
        matrix,
        interpretation: "correlation is an observable signal, not proof of response causality",
    })
}

pub fn query_e2e_dirty_counts(context: E2eRunContext, api: &str) -> Result<E2eDirtyCounts> {
    let state = finalized_focused_state(context, api)?;
    let payload = std::fs::read(&state.aggregate_report).with_context(|| {
        format!(
            "failed to read runner-owned aggregate evidence {}",
            state.aggregate_report.display()
        )
    })?;
    let report: Value = serde_json::from_slice(&payload).context("invalid aggregate evidence")?;
    let complete = report
        .get("complete")
        .and_then(Value::as_bool)
        .context("aggregate evidence has no complete flag")?;
    let dirty = report
        .get("dirty")
        .and_then(Value::as_bool)
        .context("aggregate evidence has no dirty flag")?;
    let event_counts = report
        .pointer("/counts/events")
        .cloned()
        .context("aggregate evidence has no event counts")?;
    ensure!(
        event_counts.is_object(),
        "aggregate event counts must be an object"
    );
    Ok(E2eDirtyCounts {
        complete,
        dirty,
        event_counts,
    })
}

fn finalized_focused_state(context: E2eRunContext, api: &str) -> Result<model::ActiveRunState> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused_root = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !focused_root.join(".active").exists() && !layout.active_dir.exists(),
        "bounded evidence is unavailable while an E2E attempt is active"
    );
    let state_path = focused_root.join("latest/state.yaml");
    ensure!(
        state_path.is_file(),
        "no finalized focused E2E evidence exists for API {api:?}"
    );
    let state: model::ActiveRunState = store::read_yaml(&state_path)?;
    ensure!(
        state.status.is_terminal(),
        "focused E2E evidence is not terminal"
    );
    ensure!(
        state.apis.iter().any(|candidate| candidate.group_id == api),
        "focused E2E evidence belongs to another API"
    );
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::E2eValuePresence;

    #[test]
    fn missing_and_json_null_have_different_projection_keys() {
        let missing = E2eValueObservation {
            presence: E2eValuePresence::Missing,
            value: None,
        };
        let json_null = E2eValueObservation {
            presence: E2eValuePresence::Present,
            value: Some(Value::Null),
        };
        assert_ne!(
            serde_json::to_string(&missing).unwrap(),
            serde_json::to_string(&json_null).unwrap()
        );
    }
}
