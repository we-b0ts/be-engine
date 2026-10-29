use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dirty_evidence::{self, E2eDirtyCounts};
use super::result::{
    E2eResponseUnavailableReason, E2eValueObservation, E2eValuePresence,
    RESPONSE_AVAILABILITY_POINTER, response_observation, response_observation_with_status,
    response_pointer_pattern, response_pointer_scope,
};
use super::{E2eRunContext, config, model, store};
use crate::replay::{
    ResponseAssertionCaseReport, ResponseBodyAssertionReport, ResponseBodyCodec,
    ResponseDifferenceKind, ResponseGatewayProtocol,
};

const MAX_DISTINCT_SOURCE_VALUES: usize = 8;
const RESPONSE_DIFFERENCE_PAGE_SIZE: usize = 20;
const MAX_TARGET_DIAGNOSTIC_BYTES: usize = 16 * 1024;

mod interaction;

pub(crate) fn finalized_focused_attempt_summary(
    context: E2eRunContext,
    api: &str,
) -> Result<super::E2eFocusedAttemptSummary> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let (state, _) = finalized_focused_evidence(context, api)?;
    let inventory = crate::case_group::load_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )?;
    let group = inventory
        .groups
        .iter()
        .find(|group| group.group_id == api)
        .with_context(|| format!("canonical case inventory has no API {api:?}"))?;
    super::case_selection::validate_group(&state, group)?;
    ensure!(
        state.cases.iter().all(|case| case.group_id == api)
            && state.case_source == inventory.case_source
            && state.source_revision == inventory.source_revision,
        "focused attempt does not match the canonical API case inventory"
    );
    Ok(super::E2eFocusedAttemptSummary {
        attempt: state.sequence,
        passed: state.status == model::RunStatus::Successful,
        case_source: state.case_source,
        case_inventory_id: group.case_inventory_id.clone(),
        selected_case_ids: state
            .cases
            .iter()
            .map(|case| case.case_id.clone())
            .collect(),
    })
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<E2eResponseUnavailableReason>,
    pub expected: E2eValueObservation,
    pub actual: E2eValueObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_diagnosis: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eCaseResponseDifferences {
    pub case_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_protocol: Option<ResponseGatewayProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_codec: Option<ResponseBodyCodec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_diagnosis: Option<ResponseBodyAssertionReport>,
    pub total_differences: usize,
    pub offset: usize,
    pub returned_differences: usize,
    pub omitted_differences: usize,
    pub differences: Vec<E2eCaseResponseDifference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eTargetLog {
    pub path: PathBuf,
    pub available: bool,
    pub bytes: usize,
    pub omitted_bytes: usize,
    pub tail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eTargetRuntimeDiagnostics {
    pub attempt: u64,
    pub replay_stdout: E2eTargetLog,
    pub replay_stderr: E2eTargetLog,
    pub stdout: E2eTargetLog,
    pub stderr: E2eTargetLog,
    pub state_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
}

pub fn query_e2e_target_runtime_diagnostics(
    context: E2eRunContext,
    api: &str,
) -> Result<E2eTargetRuntimeDiagnostics> {
    let (state, latest_dir) = finalized_focused_evidence(context, api)?;
    let reports = latest_dir.join("reports");
    let state_path = reports.join("target-state.json");
    let runtime_state = match std::fs::read(&state_path) {
        Ok(payload) => Some(
            serde_json::from_slice(&payload).context("invalid target runtime state evidence")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read target runtime state {}",
                    state_path.display()
                )
            });
        }
    };
    Ok(E2eTargetRuntimeDiagnostics {
        attempt: state.sequence,
        replay_stdout: read_target_log(reports.join("replay.stdout.log"))?,
        replay_stderr: read_target_log(reports.join("replay.stderr.log"))?,
        stdout: read_target_log(reports.join("target.stdout.log"))?,
        stderr: read_target_log(reports.join("target.stderr.log"))?,
        state_path,
        state: runtime_state,
    })
}

fn read_target_log(path: PathBuf) -> Result<E2eTargetLog> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(E2eTargetLog {
                path,
                available: false,
                bytes: 0,
                omitted_bytes: 0,
                tail: String::new(),
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read target log {}", path.display()));
        }
    };
    let bytes = usize::try_from(file.metadata()?.len())?;
    let omitted_bytes = bytes.saturating_sub(MAX_TARGET_DIAGNOSTIC_BYTES);
    file.seek(SeekFrom::Start(omitted_bytes as u64))?;
    let mut payload = Vec::new();
    file.take(MAX_TARGET_DIAGNOSTIC_BYTES as u64)
        .read_to_end(&mut payload)?;
    Ok(E2eTargetLog {
        path,
        available: true,
        bytes,
        omitted_bytes,
        tail: String::from_utf8_lossy(&payload).into_owned(),
    })
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
    let Some(assertion) = case.response_assertion.as_ref() else {
        ensure!(
            case.assertion_passed == Some(false),
            "case {case_id:?} has no response assertion evidence"
        );
        return unavailable_response_page(case_id, case.response_unavailable_reason, offset);
    };
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

fn unavailable_response_page(
    case_id: &str,
    reason: Option<E2eResponseUnavailableReason>,
    offset: usize,
) -> Result<E2eCaseResponseDifferences> {
    ensure!(
        offset == 0,
        "response difference page is outside the current assertion detail"
    );
    Ok(E2eCaseResponseDifferences {
        case_id: case_id.to_string(),
        gateway_protocol: None,
        body_codec: None,
        body_diagnosis: None,
        total_differences: 1,
        offset,
        returned_differences: 1,
        omitted_differences: 0,
        differences: vec![E2eCaseResponseDifference {
            pointer: RESPONSE_AVAILABILITY_POINTER.to_string(),
            pointer_pattern: RESPONSE_AVAILABILITY_POINTER.to_string(),
            difference_kind: ResponseDifferenceKind::ResponseUnavailable,
            unavailable_reason: reason,
            expected: E2eValueObservation {
                jwt_candidate: false,
                presence: E2eValuePresence::Present,
                value: None,
            },
            actual: E2eValueObservation {
                jwt_candidate: false,
                presence: E2eValuePresence::Unavailable,
                value: None,
            },
            interaction_diagnosis: None,
        }],
        next_offset: None,
    })
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
    let mut differences = report.differences[offset..end]
        .iter()
        .map(|difference| E2eCaseResponseDifference {
            pointer: difference.pointer.clone(),
            pointer_pattern: response_pointer_pattern(&difference.pointer),
            difference_kind: difference.kind,
            unavailable_reason: None,
            expected: response_observation_with_status(
                &assertion.expected_response,
                &difference.pointer,
                difference.expected_status,
            ),
            actual: response_observation_with_status(
                &assertion.actual_response,
                &difference.pointer,
                difference.actual_status,
            ),
            interaction_diagnosis: None,
        })
        .collect::<Vec<_>>();
    interaction::diagnose_page(
        &mut differences,
        &assertion.expected_response,
        &assertion.actual_response,
    );
    Ok(E2eCaseResponseDifferences {
        case_id: case_id.to_string(),
        gateway_protocol: Some(report.gateway_protocol),
        body_codec: Some(report.body_codec),
        body_diagnosis: report.body_diagnosis.clone(),
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
    super::evidence_admission::require_aggregate_report(&state)?;
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

pub(crate) fn query_http_cross_case_candidates(context: E2eRunContext, api: &str) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    Ok(crate::replay::http_cross_case::discover(&state.case_source, &state.replay_report, true)
        .unwrap_or_else(|_| serde_json::json!({"candidates": [], "unavailable": "cross-case source evidence could not be inspected; existing dirty evidence remains authoritative"})))
}

pub(crate) fn query_redis_unordered_candidates(context: E2eRunContext, api: &str) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    Ok(crate::replay::redis_value::evidence::discover(&state.replay_report)
        .unwrap_or_else(|_| serde_json::json!({"candidates": [], "omitted_candidates": 0, "requires_fresh_replay": true, "unavailable": "Redis unordered evidence is unavailable; rerun Replay"})))
}

pub(crate) fn query_execution_context(
    context: E2eRunContext,
    api: &str,
    attempt: u64,
) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    ensure!(
        state.sequence == attempt,
        "execution failures belong to attempt {}, not active issue attempt {attempt}",
        state.sequence
    );
    Ok(serde_json::json!({
        "attempt":state.sequence,"status":state.status,"replay_finalized":state.replay_finalized,
        "session_id":state.session_id,
        "executed_cases":state.cases.iter().filter(|case|case.assertion_passed.is_some()).count(),
        "selected_cases":state.cases.len(),
        "case_selection":super::case_selection::diagnosis(&state),
        "lifecycle_errors":state.errors.iter().rev().take(3).rev().map(|error|super::result::bounded_error(error)).collect::<Vec<_>>(),
        "execution_failures":super::execution_failure::diagnosis(&state),
        "execution_failures_summary":super::execution_failure::summary(&state)
    }))
}

pub(crate) fn query_execution_failure_page(
    context: E2eRunContext,
    api: &str,
    attempt: u64,
    offset: usize,
) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    ensure!(
        state.sequence == attempt,
        "execution failures belong to attempt {}, not active issue attempt {attempt}",
        state.sequence
    );
    let mut page = super::execution_failure::page(&state, offset)?;
    page["attempt"] = attempt.into();
    page["status"] = serde_json::to_value(state.status)?;
    page["replay_finalized"] = state.replay_finalized.into();
    page["selected_cases"] = state.cases.len().into();
    page["case_selection"] = serde_json::json!(super::case_selection::diagnosis(&state));
    Ok(page)
}

pub(crate) fn query_dependency_request_candidates(
    context: E2eRunContext,
    api: &str,
) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    let report: Value = serde_json::from_slice(&std::fs::read(&state.replay_report)?)?;
    Ok(crate::replay::discover_dependency_request_candidates(
        &report,
    ))
}

pub(crate) fn query_dynamic_capture_candidates(context: E2eRunContext, api: &str) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    let report: Value = serde_json::from_slice(&std::fs::read(&state.replay_report)?)?;
    Ok(report["replay_policy"]["dynamic_capture_candidates"]
        .as_array()
        .map_or_else(
            || serde_json::json!([]),
            |items| Value::Array(items.clone()),
        ))
}

pub(crate) fn query_rule_policy_freshness(
    context: E2eRunContext,
    api: &str,
    current_fingerprint: &str,
) -> crate::replay::ReplayEvidencePolicyFreshness {
    let identity = (|| -> Result<Option<String>> {
        let evidence = super::resolve_e2e_response_rule_evidence(context, api)?;
        let report: Value = serde_json::from_slice(&std::fs::read(evidence.replay)?)?;
        Ok(report["replay_policy"]["fingerprint"]
            .as_str()
            .filter(|_| report["finalized"] == true)
            .map(str::to_owned))
    })();
    match identity {
        Ok(identity) => crate::replay::ReplayEvidencePolicyFreshness::new(
            identity.as_deref(),
            current_fingerprint,
        ),
        Err(error) => crate::replay::ReplayEvidencePolicyFreshness::unavailable(
            current_fingerprint,
            format!("{error:#}"),
        ),
    }
}

pub(crate) fn query_http_unordered_candidates(context: E2eRunContext, api: &str) -> Result<Value> {
    let state = finalized_focused_state(context, api)?;
    Ok(crate::replay::http_unordered::evidence::discover(&state.replay_report)
        .unwrap_or_else(|_| serde_json::json!({"candidates": [], "omitted_candidates": 0, "requires_fresh_replay": true, "unavailable": "HTTP unordered evidence is unavailable; rerun Replay"})))
}

fn finalized_focused_state(context: E2eRunContext, api: &str) -> Result<model::ActiveRunState> {
    finalized_focused_evidence(context, api).map(|(state, _)| state)
}

pub(super) fn finalized_focused_evidence(
    context: E2eRunContext,
    api: &str,
) -> Result<(model::ActiveRunState, PathBuf)> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused_root = super::evidence_admission::focused_root(&layout, api)?;
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
    Ok((state, focused_root.join("latest")))
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
            jwt_candidate: false,
            presence: E2eValuePresence::Missing,
            value: None,
        };
        let json_null = E2eValueObservation {
            jwt_candidate: false,
            presence: E2eValuePresence::Present,
            value: Some(Value::Null),
        };
        assert_ne!(
            serde_json::to_string(&missing).unwrap(),
            serde_json::to_string(&json_null).unwrap()
        );
    }

    #[test]
    fn target_log_projection_is_bounded_to_the_latest_output() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target.stderr.log");
        let mut payload = vec![b'a'; MAX_TARGET_DIAGNOSTIC_BYTES];
        payload.extend_from_slice(b"latest failure\n");
        std::fs::write(&path, &payload).unwrap();

        let log = read_target_log(path.clone()).unwrap();

        assert!(log.available);
        assert_eq!(log.path, path);
        assert_eq!(log.bytes, payload.len());
        assert_eq!(log.omitted_bytes, b"latest failure\n".len());
        assert!(log.tail.ends_with("latest failure\n"));
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
            method: "GET".to_string(),
            path: "/api".to_string(),
            gateway_protocol: ResponseGatewayProtocol::Http,
            body_codec: ResponseBodyCodec::Json,
            body_diagnosis: None,
            difference_count: differences.len(),
            difference_index: differences.clone(),
            representative_difference: differences.first().cloned(),
            detail_report: PathBuf::from("detail.json"),
            detail_fingerprint: "detail".to_string(),
            request: PathBuf::from("request.json"),
            expected_response: expected,
            actual_response: actual,
            policy_path: "replay.yaml".to_string(),
            policy_fingerprint: "policy".to_string(),
        };
        let report: ResponseAssertionCaseReport = serde_json::from_value(serde_json::json!({
            "version": 3,
            "case_id": "case-1",
            "method": "GET",
            "path": "/api",
            "request_path": "request.json",
            "policy_path": "replay.yaml",
            "policy_fingerprint": "policy",
            "expected_response_path": assertion.expected_response.display().to_string(),
            "expected_response_fingerprint": "expected",
            "actual_response_path": assertion.actual_response.display().to_string(),
            "actual_response_fingerprint": "actual",
            "gateway_protocol": "http",
            "body_codec": "json",
            "differences": differences,
            "applied_generated_rule_ids": [],
            "unused_applicable_generated_rule_ids": [],
            "generated_scalar_candidates": [],
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

    #[test]
    fn unavailable_response_is_exposed_as_one_difference() {
        let page = unavailable_response_page(
            "case-1",
            Some(E2eResponseUnavailableReason::TargetConnectionClosed),
            0,
        )
        .unwrap();

        assert_eq!(page.total_differences, 1);
        assert_eq!(page.returned_differences, 1);
        assert_eq!(page.omitted_differences, 0);
        assert_eq!(page.next_offset, None);
        let difference = &page.differences[0];
        assert_eq!(difference.pointer, RESPONSE_AVAILABILITY_POINTER);
        assert_eq!(
            difference.difference_kind,
            ResponseDifferenceKind::ResponseUnavailable
        );
        assert_eq!(
            difference.unavailable_reason,
            Some(E2eResponseUnavailableReason::TargetConnectionClosed)
        );
        assert_eq!(difference.expected.presence, E2eValuePresence::Present);
        assert_eq!(difference.actual.presence, E2eValuePresence::Unavailable);
        assert!(unavailable_response_page("case-1", None, 20).is_err());
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
