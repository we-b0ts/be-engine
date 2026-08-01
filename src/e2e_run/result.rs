use std::path::{Path, PathBuf};

use serde::Serialize;

use super::model::{ActiveRunState, RunLayout, RunStatus};
use super::support::status_label;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eResponseGate {
    Passed,
    Nonpassing,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eReplayGate {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum E2eDependencyGate {
    Clean,
    Dirty,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct E2eVerificationGates {
    pub responses: E2eResponseGate,
    pub replay: E2eReplayGate,
    pub dependencies: E2eDependencyGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct E2eReportPaths {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eRunResult {
    pub run_key: String,
    pub sequence: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub reports: E2eReportPaths,
    pub latest_state: PathBuf,
    pub progress: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eApiRunResult {
    pub run_key: String,
    pub api: String,
    pub attempt: u64,
    pub status: String,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    pub reports: E2eReportPaths,
    pub latest_state: PathBuf,
    pub progress: PathBuf,
}

pub(super) fn run_result(layout: &RunLayout, state: &ActiveRunState) -> E2eRunResult {
    E2eRunResult {
        run_key: state.run_key.clone(),
        sequence: state.sequence,
        status: status_label(state.status).to_string(),
        passed: state.status == RunStatus::Successful,
        gates: verification_gates(state),
        reports: report_paths(layout, state),
        latest_state: layout.latest_dir.join("state.yaml"),
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
        reports: report_paths(layout, state),
        latest_state: layout.latest_dir.join("state.yaml"),
        progress: layout.progress_path.clone(),
    }
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

fn report_paths(layout: &RunLayout, state: &ActiveRunState) -> E2eReportPaths {
    E2eReportPaths {
        replay: existing_published_path(layout, &state.replay_report),
        assertions: existing_published_path(layout, &state.assertions_report),
        aggregate: existing_published_path(layout, &state.aggregate_report),
    }
}

fn existing_published_path(layout: &RunLayout, path: &Path) -> Option<PathBuf> {
    let published = path
        .strip_prefix(&layout.active_dir)
        .map(|relative| layout.latest_dir.join(relative))
        .unwrap_or_else(|_| path.to_path_buf());
    published.is_file().then_some(published)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};

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
}
