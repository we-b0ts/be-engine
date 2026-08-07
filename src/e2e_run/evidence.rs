use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dirty_evidence::{self, E2eDirtyCounts};
use super::result::{
    E2eValueObservation, response_observation, response_pointer_pattern, response_pointer_scope,
};
use super::{E2eRunContext, config, model, store, support};
use crate::replay::{ResponseAssertionCaseReport, ResponseDifferenceKind};

const MAX_DISTINCT_SOURCE_VALUES: usize = 8;
const RESPONSE_DIFFERENCE_PAGE_SIZE: usize = 20;

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
pub struct E2eCaseResponseDifference {
    pub pointer: String,
    pub pointer_pattern: String,
    pub difference_kind: ResponseDifferenceKind,
    pub expected: E2eValueObservation,
    pub actual: E2eValueObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eCaseResponseDifferences {
    pub case_id: String,
    pub total_differences: usize,
    pub offset: usize,
    pub returned_differences: usize,
    pub omitted_differences: usize,
    pub differences: Vec<E2eCaseResponseDifference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
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
        pointer_scope: response_pointer_scope(pointer),
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

pub fn query_e2e_case_response_differences(
    context: E2eRunContext,
    api: &str,
    case_id: &str,
    offset: usize,
) -> Result<E2eCaseResponseDifferences> {
    ensure!(
        offset.is_multiple_of(RESPONSE_DIFFERENCE_PAGE_SIZE),
        "response difference offset must identify a coordinator-issued page"
    );
    let state = finalized_focused_state(context, api)?;
    let case = state
        .cases
        .iter()
        .find(|case| case.case_id == case_id)
        .with_context(|| format!("focused E2E evidence has no case {case_id:?}"))?;
    let assertion = case
        .response_assertion
        .as_ref()
        .with_context(|| format!("case {case_id:?} has no response assertion evidence"))?;
    let payload = std::fs::read(&assertion.detail_report).with_context(|| {
        format!(
            "failed to read response assertion detail {}",
            assertion.detail_report.display()
        )
    })?;
    ensure!(
        crate::verification_progress::fingerprint(&payload) == assertion.detail_fingerprint,
        "response assertion detail changed after focused E2E publication"
    );
    let report: ResponseAssertionCaseReport =
        serde_json::from_slice(&payload).context("invalid response assertion detail evidence")?;
    ensure!(
        report.case_id == case_id,
        "response assertion detail belongs to another case"
    );
    ensure!(
        report.differences.len() == assertion.difference_count,
        "response assertion detail count differs from focused E2E state"
    );
    response_difference_page(case_id, assertion, &report, offset)
}

fn response_difference_page(
    case_id: &str,
    assertion: &model::ResponseAssertionSummary,
    report: &ResponseAssertionCaseReport,
    offset: usize,
) -> Result<E2eCaseResponseDifferences> {
    ensure!(
        offset < report.differences.len(),
        "response difference page is outside the current assertion detail"
    );
    let end = offset
        .saturating_add(RESPONSE_DIFFERENCE_PAGE_SIZE)
        .min(report.differences.len());
    let differences = report.differences[offset..end]
        .iter()
        .map(|difference| E2eCaseResponseDifference {
            pointer: difference.pointer.clone(),
            pointer_pattern: response_pointer_pattern(&difference.pointer),
            difference_kind: difference.kind,
            expected: response_observation(&assertion.expected_response, &difference.pointer),
            actual: response_observation(&assertion.actual_response, &difference.pointer),
        })
        .collect::<Vec<_>>();
    Ok(E2eCaseResponseDifferences {
        case_id: case_id.to_string(),
        total_differences: report.differences.len(),
        offset,
        returned_differences: differences.len(),
        omitted_differences: report.differences.len().saturating_sub(end),
        differences,
        next_offset: (end < report.differences.len()).then_some(end),
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
    dirty_evidence::build(&state, complete, dirty)
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
    use crate::replay::ResponseDifference;
    use std::path::PathBuf;

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

    #[test]
    fn response_difference_pages_are_bounded_and_preserve_all_differences() {
        let temp = tempfile::tempdir().unwrap();
        let expected = temp.path().join("expected-response.json");
        let actual = temp.path().join("actual-response.json");
        let expected_items = (0..21)
            .map(|index| serde_json::json!({"value": index}))
            .collect::<Vec<_>>();
        let actual_items = (0..21).map(|_| serde_json::json!({})).collect::<Vec<_>>();
        write_response(&expected, serde_json::json!({"items": expected_items}));
        write_response(&actual, serde_json::json!({"items": actual_items}));
        let differences = (0..21)
            .map(|index| ResponseDifference {
                pointer: format!("/items/{index}/value"),
                kind: ResponseDifferenceKind::MissingActual,
                expected_type: Some("number".to_string()),
                actual_type: None,
                expected_status: None,
                actual_status: None,
            })
            .collect::<Vec<_>>();
        let assertion = model::ResponseAssertionSummary {
            passed: false,
            difference_count: differences.len(),
            difference_index: differences.clone(),
            representative_difference: differences.first().cloned(),
            detail_report: PathBuf::from("detail.json"),
            detail_fingerprint: "detail".to_string(),
            expected_response: expected,
            actual_response: actual,
            policy_path: "replay.yaml".to_string(),
            policy_fingerprint: "policy".to_string(),
        };
        let report: ResponseAssertionCaseReport = serde_json::from_value(serde_json::json!({
            "version": 1,
            "case_id": "case-1",
            "method": "GET",
            "path": "/api",
            "policy_path": "replay.yaml",
            "policy_fingerprint": "policy",
            "expected_response_path": assertion.expected_response.display().to_string(),
            "expected_response_fingerprint": "expected",
            "actual_response_path": assertion.actual_response.display().to_string(),
            "actual_response_fingerprint": "actual",
            "body_mode": "json_structural",
            "differences": differences,
            "applied_dynamic_rule_ids": [],
            "unused_applicable_dynamic_rule_ids": [],
            "dynamic_candidates": [],
            "applied_unordered_rule_ids": [],
            "unused_applicable_unordered_rule_ids": [],
            "applied_counter_rule_ids": [],
            "unused_applicable_counter_rule_ids": [],
            "unordered_candidates": [],
            "passed": false,
        }))
        .unwrap();

        let first = response_difference_page("case-1", &assertion, &report, 0).unwrap();
        assert_eq!(first.total_differences, 21);
        assert_eq!(first.returned_differences, 20);
        assert_eq!(first.omitted_differences, 1);
        assert_eq!(first.next_offset, Some(20));
        assert_eq!(first.differences[0].pointer_pattern, "/items/*/value");
        assert_eq!(
            first.differences[0].expected.presence,
            E2eValuePresence::Present
        );
        assert_eq!(
            first.differences[0].actual.presence,
            E2eValuePresence::Missing
        );

        let second = response_difference_page("case-1", &assertion, &report, 20).unwrap();
        assert_eq!(second.returned_differences, 1);
        assert_eq!(second.omitted_differences, 0);
        assert_eq!(second.next_offset, None);
        assert_eq!(second.differences[0].pointer, "/items/20/value");
    }

    fn write_response(path: &std::path::Path, body: Value) {
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "status": 200,
                "body": {
                    "encoding": "utf8",
                    "data": serde_json::to_string(&body).unwrap(),
                    "truncated": false
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
