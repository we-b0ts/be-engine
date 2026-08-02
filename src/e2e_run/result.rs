use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::model::{ActiveRunState, RunLayout, RunStatus};
use super::support::status_label;
use crate::replay::ResponseDifferenceKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eResponseGate {
    Passed,
    Nonpassing,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eReplayGate {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eDependencyGate {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eVerificationGates {
    pub responses: E2eResponseGate,
    pub replay: E2eReplayGate,
    pub dependencies: E2eDependencyGate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eRunResult {
    pub run_key: String,
    pub sequence: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub diagnosis: E2eDiagnosis,
    pub progress: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eApiRunResult {
    pub run_key: String,
    pub api: String,
    pub attempt: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub diagnosis: E2eDiagnosis,
    pub progress: PathBuf,
}

pub(super) fn run_result(layout: &RunLayout, state: &ActiveRunState) -> E2eRunResult {
    E2eRunResult {
        run_key: state.run_key.clone(),
        sequence: state.sequence,
        status: status_label(state.status).to_string(),
        passed: state.status == RunStatus::Successful,
        gates: verification_gates(state),
        diagnosis: diagnosis(layout, state),
        progress: layout.progress_path.clone(),
    }
}

pub(super) fn api_result(
    layout: &RunLayout,
    state: &ActiveRunState,
    api: &str,
    attempt: u64,
) -> E2eApiRunResult {
    E2eApiRunResult {
        run_key: state.run_key.clone(),
        api: api.to_string(),
        attempt,
        status: status_label(state.status).to_string(),
        passed: state.status == RunStatus::Successful,
        gates: verification_gates(state),
        diagnosis: diagnosis(layout, state),
        progress: layout.progress_path.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eDiagnosisCounts {
    pub selected: usize,
    pub executed: usize,
    pub response_passed: usize,
    pub response_nonpassing: usize,
    pub response_incomplete: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eFailureCluster {
    pub pointer: String,
    pub difference_kind: ResponseDifferenceKind,
    pub cases: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eRepresentativeDifference {
    pub case_id: String,
    pub pointer: String,
    pub difference_kind: ResponseDifferenceKind,
    pub expected: E2eValueObservation,
    pub actual: E2eValueObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eValuePresence {
    Present,
    Missing,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eValueObservation {
    pub presence: E2eValuePresence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eDiagnosis {
    pub counts: E2eDiagnosisCounts,
    pub failure_clusters: Vec<E2eFailureCluster>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative: Option<E2eRepresentativeDifference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle_errors: Vec<String>,
}

fn diagnosis(layout: &RunLayout, state: &ActiveRunState) -> E2eDiagnosis {
    let mut clusters = BTreeMap::<(String, ResponseDifferenceKind), usize>::new();
    let mut representatives =
        BTreeMap::<(String, ResponseDifferenceKind), (String, PathBuf, PathBuf)>::new();
    for case in &state.cases {
        let Some(assertion) = &case.response_assertion else {
            continue;
        };
        let Some(difference) = &assertion.representative_difference else {
            continue;
        };
        let key = (difference.pointer.clone(), difference.kind);
        *clusters.entry(key.clone()).or_default() += 1;
        representatives.entry(key).or_insert_with(|| {
            (
                case.case_id.clone(),
                assertion.expected_response.clone(),
                published_path(layout, &assertion.actual_response),
            )
        });
    }
    let mut failure_clusters = clusters
        .into_iter()
        .map(|((pointer, difference_kind), cases)| E2eFailureCluster {
            pointer,
            difference_kind,
            cases,
        })
        .collect::<Vec<_>>();
    failure_clusters.sort_by(|left, right| {
        right
            .cases
            .cmp(&left.cases)
            .then_with(|| left.pointer.cmp(&right.pointer))
            .then_with(|| left.difference_kind.cmp(&right.difference_kind))
    });
    let representative = failure_clusters.first().and_then(|cluster| {
        representatives
            .get(&(cluster.pointer.clone(), cluster.difference_kind))
            .map(|(case_id, expected, actual)| E2eRepresentativeDifference {
                case_id: case_id.clone(),
                pointer: cluster.pointer.clone(),
                difference_kind: cluster.difference_kind,
                expected: response_observation(expected, &cluster.pointer),
                actual: response_observation(actual, &cluster.pointer),
            })
    });
    let executed = state
        .cases
        .iter()
        .filter(|case| case.assertion_passed.is_some())
        .count();
    let response_passed = state
        .cases
        .iter()
        .filter(|case| case.assertion_passed == Some(true))
        .count();
    let response_nonpassing = state
        .cases
        .iter()
        .filter(|case| case.assertion_passed == Some(false))
        .count();
    E2eDiagnosis {
        counts: E2eDiagnosisCounts {
            selected: state.cases.len(),
            executed,
            response_passed,
            response_nonpassing,
            response_incomplete: state.cases.len().saturating_sub(executed),
        },
        failure_clusters,
        representative,
        lifecycle_errors: state
            .errors
            .iter()
            .take(3)
            .map(|error| bounded_error(error))
            .collect(),
    }
}

fn bounded_error(error: &str) -> String {
    const LIMIT: usize = 512;
    let one_line = error.replace(['\r', '\n'], " ");
    let mut chars = one_line.chars();
    let bounded = chars.by_ref().take(LIMIT).collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else {
        bounded
    }
}

pub(super) fn response_observation(path: &Path, pointer: &str) -> E2eValueObservation {
    let Ok(bytes) = std::fs::read(path) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    let Ok(response) = serde_json::from_slice::<Value>(&bytes) else {
        return observation(E2eValuePresence::Unavailable, None);
    };
    if pointer == "$status" {
        return match response.get("status") {
            Some(value) => observation(E2eValuePresence::Present, Some(bounded(value, pointer))),
            None => observation(E2eValuePresence::Missing, None),
        };
    }
    let Some(body) = response.get("body") else {
        return observation(E2eValuePresence::Missing, None);
    };
    let Some(data) = body.get("data").and_then(Value::as_str) else {
        return observation(E2eValuePresence::Missing, None);
    };
    let decoded = match body.get("encoding").and_then(Value::as_str) {
        Some("utf8") => data.as_bytes().to_vec(),
        Some("base64") => match STANDARD.decode(data) {
            Ok(value) => value,
            Err(_) => return observation(E2eValuePresence::Unavailable, None),
        },
        _ => return observation(E2eValuePresence::Unavailable, None),
    };
    if pointer == "$body" {
        let value = String::from_utf8(decoded)
            .map(Value::String)
            .unwrap_or_else(|error| {
                Value::String(format!("<binary bytes={}>", error.as_bytes().len()))
            });
        return observation(E2eValuePresence::Present, Some(bounded(&value, pointer)));
    }
    let Ok(json) = serde_json::from_slice::<Value>(&decoded) else {
        return observation(E2eValuePresence::NotApplicable, None);
    };
    match json.pointer(pointer) {
        Some(value) => observation(E2eValuePresence::Present, Some(bounded(value, pointer))),
        None => observation(E2eValuePresence::Missing, None),
    }
}

fn observation(presence: E2eValuePresence, value: Option<Value>) -> E2eValueObservation {
    E2eValueObservation { presence, value }
}

fn bounded(value: &Value, pointer: &str) -> Value {
    if sensitive_pointer(pointer) {
        return Value::String(match value {
            Value::String(value) => format!("<redacted string bytes={}>", value.len()),
            _ => "<redacted>".to_string(),
        });
    }
    match value {
        Value::String(value) if value.len() > 256 => {
            Value::String(format!("<string bytes={}>", value.len()))
        }
        Value::Array(values) => {
            let bytes = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
            if bytes > 1_024 {
                Value::String(format!("<array items={} bytes={bytes}>", values.len()))
            } else {
                value.clone()
            }
        }
        Value::Object(values) => {
            let bytes = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
            if bytes > 1_024 {
                Value::String(format!("<object keys={} bytes={bytes}>", values.len()))
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

fn sensitive_pointer(pointer: &str) -> bool {
    pointer.split('/').any(|token| {
        let token = token.to_ascii_lowercase();
        [
            "authorization",
            "cookie",
            "password",
            "passwd",
            "secret",
            "token",
            "ticket",
            "credential",
        ]
        .iter()
        .any(|sensitive| token.contains(sensitive))
    })
}

fn published_path(layout: &RunLayout, path: &Path) -> PathBuf {
    path.strip_prefix(&layout.active_dir)
        .map(|relative| layout.latest_dir.join(relative))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn verification_gates(state: &ActiveRunState) -> E2eVerificationGates {
    let responses = response_gate(state.cases.iter().map(|case| case.assertion_passed));
    let replay = if state.replay_finalized && state.aggregate_complete {
        E2eReplayGate::Complete
    } else {
        E2eReplayGate::Incomplete
    };
    let dependencies = match replay {
        E2eReplayGate::Incomplete => E2eDependencyGate::Unknown,
        E2eReplayGate::Complete if state.aggregate_clean => E2eDependencyGate::Clean,
        E2eReplayGate::Complete => E2eDependencyGate::Dirty,
    };
    E2eVerificationGates {
        responses,
        replay,
        dependencies,
    }
}

fn response_gate(assertions: impl Iterator<Item = Option<bool>>) -> E2eResponseGate {
    let mut observed = false;
    let mut incomplete = false;
    for assertion in assertions {
        observed = true;
        match assertion {
            Some(true) => {}
            Some(false) => return E2eResponseGate::Nonpassing,
            None => incomplete = true,
        }
    }
    if observed && !incomplete {
        E2eResponseGate::Passed
    } else {
        E2eResponseGate::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
    use crate::e2e_run::model::ResponseAssertionSummary;
    use crate::replay::ResponseDifference;

    #[test]
    fn response_gate_distinguishes_nonpassing_and_incomplete_evidence() {
        assert_eq!(
            response_gate([Some(true), Some(true)].into_iter()),
            E2eResponseGate::Passed
        );
        assert_eq!(
            response_gate([Some(true), Some(false), None].into_iter()),
            E2eResponseGate::Nonpassing
        );
        assert_eq!(
            response_gate([Some(true), None].into_iter()),
            E2eResponseGate::Incomplete
        );
        assert_eq!(
            response_gate(std::iter::empty()),
            E2eResponseGate::Incomplete
        );
    }

    #[test]
    fn gate_values_serialize_as_stable_diagnostic_labels() {
        let gates = E2eVerificationGates {
            responses: E2eResponseGate::Passed,
            replay: E2eReplayGate::Complete,
            dependencies: E2eDependencyGate::Dirty,
        };
        assert_eq!(
            serde_json::to_value(gates).unwrap(),
            serde_json::json!({
                "responses": "passed",
                "replay": "complete",
                "dependencies": "dirty"
            })
        );
    }

    #[test]
    fn finalized_dirty_evidence_is_distinct_from_incomplete_replay() {
        let inventory = CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api".to_string(),
                method: "GET".to_string(),
                source_route: "/api".to_string(),
                pattern: None,
                case_inventory_id: "inventory".to_string(),
                cases: vec![CanonicalCase {
                    case_id: "case-1".to_string(),
                    case_dir: PathBuf::from("/cases/case-1"),
                    recorded_at: None,
                }],
            }],
        };
        let mut state =
            ActiveRunState::new("run".to_string(), 1, &inventory, None, Path::new("/active"));

        assert_eq!(
            verification_gates(&state),
            E2eVerificationGates {
                responses: E2eResponseGate::Incomplete,
                replay: E2eReplayGate::Incomplete,
                dependencies: E2eDependencyGate::Unknown,
            }
        );

        state.cases[0].assertion_passed = Some(true);
        state.replay_finalized = true;
        state.aggregate_complete = true;
        state.aggregate_clean = false;
        assert_eq!(
            verification_gates(&state),
            E2eVerificationGates {
                responses: E2eResponseGate::Passed,
                replay: E2eReplayGate::Complete,
                dependencies: E2eDependencyGate::Dirty,
            }
        );
    }

    #[test]
    fn diagnosis_distinguishes_json_null_from_a_missing_value() {
        let temp = tempfile::tempdir().unwrap();
        let active_dir = temp.path().join("active");
        let latest_dir = temp.path().join("latest");
        std::fs::create_dir_all(&active_dir).unwrap();
        std::fs::create_dir_all(&latest_dir).unwrap();
        let expected = temp.path().join("expected-response.json");
        let published_actual = latest_dir.join("actual-response.json");
        write_response(&expected, serde_json::json!({"value": null}));
        write_response(&published_actual, serde_json::json!({}));

        let inventory = one_case_inventory();
        let mut state = ActiveRunState::new("run".to_string(), 1, &inventory, None, &active_dir);
        state.cases[0].assertion_passed = Some(false);
        state.cases[0].response_assertion = Some(ResponseAssertionSummary {
            passed: false,
            difference_count: 1,
            representative_difference: Some(ResponseDifference {
                pointer: "/value".to_string(),
                kind: ResponseDifferenceKind::MissingActual,
                expected_type: Some("null".to_string()),
                actual_type: None,
                expected_status: None,
                actual_status: None,
            }),
            detail_report: active_dir.join("assertion-detail.json"),
            detail_fingerprint: "detail-fingerprint".to_string(),
            expected_response: expected,
            actual_response: active_dir.join("actual-response.json"),
            policy_path: "replay.yaml".to_string(),
            policy_fingerprint: "fingerprint".to_string(),
        });
        let layout = RunLayout {
            target_root: temp.path().to_path_buf(),
            run_key: "run".to_string(),
            case_source: PathBuf::from("/cases"),
            progress_path: temp.path().join("progress.yaml"),
            legacy_progress_path: temp.path().join("legacy-progress.yaml"),
            local_root: temp.path().join("local"),
            current_path: temp.path().join("current"),
            run_root: temp.path().join("run"),
            index_path: temp.path().join("index.yaml"),
            group_index_path: temp.path().join("group-index.yaml"),
            active_dir,
            latest_dir,
        };

        let report = diagnosis(&layout, &state);

        let representative = report.representative.unwrap();
        assert_eq!(representative.expected.presence, E2eValuePresence::Present);
        assert_eq!(representative.expected.value, Some(Value::Null));
        assert_eq!(representative.actual.presence, E2eValuePresence::Missing);
        assert_eq!(representative.actual.value, None);
        assert_eq!(report.failure_clusters[0].cases, 1);
    }

    #[test]
    fn diagnosis_bounds_and_redacts_representative_values() {
        assert_eq!(
            bounded(&Value::String("x".repeat(300)), "/description"),
            Value::String("<string bytes=300>".to_string())
        );
        assert_eq!(
            bounded(&Value::String("secret".to_string()), "/authorization"),
            Value::String("<redacted string bytes=6>".to_string())
        );
    }

    fn one_case_inventory() -> CaseGroupInventory {
        CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api".to_string(),
                method: "GET".to_string(),
                source_route: "/api".to_string(),
                pattern: None,
                case_inventory_id: "inventory".to_string(),
                cases: vec![CanonicalCase {
                    case_id: "case-1".to_string(),
                    case_dir: PathBuf::from("/cases/case-1"),
                    recorded_at: None,
                }],
            }],
        }
    }

    fn write_response(path: &Path, body: Value) {
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
