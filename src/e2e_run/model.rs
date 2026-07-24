use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::case_group::CaseGroupInventory;
use crate::replay::ResponseAssertionCaseReport;

pub(super) const STATE_VERSION: u32 = 1;
pub(super) const ASSERTION_REPORT_VERSION: u32 = 1;
pub(super) const DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS: u64 = 60;
pub(super) const DEFAULT_CONSECUTIVE_SUCCESSFUL_RUNS: u64 = 3;
pub(super) const DEFAULT_SUCCESSFUL_CASES: u64 = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApiVerificationThresholds {
    pub consecutive_successful_runs: u64,
    pub successful_cases: u64,
}

impl Default for ApiVerificationThresholds {
    fn default() -> Self {
        Self {
            consecutive_successful_runs: DEFAULT_CONSECUTIVE_SUCCESSFUL_RUNS,
            successful_cases: DEFAULT_SUCCESSFUL_CASES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ApiVerificationConfig {
    pub consecutive_successful_runs: u64,
    pub successful_cases: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, ApiVerificationThresholds>,
}

impl ApiVerificationConfig {
    pub(super) fn thresholds_for(&self, api_key: &str) -> ApiVerificationThresholds {
        self.overrides
            .get(api_key)
            .copied()
            .unwrap_or(ApiVerificationThresholds {
                consecutive_successful_runs: self.consecutive_successful_runs,
                successful_cases: self.successful_cases,
            })
    }
}

impl Default for ApiVerificationConfig {
    fn default() -> Self {
        let thresholds = ApiVerificationThresholds::default();
        Self {
            consecutive_successful_runs: thresholds.consecutive_successful_runs,
            successful_cases: thresholds.successful_cases,
            overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectConfig {
    pub version: u32,
    pub project_cli: PathBuf,
    pub replay_policy: PathBuf,
    #[serde(default = "default_replay_startup_timeout_seconds")]
    pub replay_startup_timeout_seconds: u64,
    #[serde(default)]
    pub api_verification: ApiVerificationConfig,
    pub pr_base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder_config: Option<PathBuf>,
    #[serde(default = "default_local_root")]
    pub local_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recording_rule: Option<String>,
    #[serde(
        default,
        rename = "required_consecutive_successful_runs",
        skip_serializing
    )]
    pub _legacy_required_consecutive_successful_runs: Option<u32>,
}

fn default_local_root() -> PathBuf {
    PathBuf::from("local")
}

fn default_replay_startup_timeout_seconds() -> u64 {
    DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedProjectConfig {
    pub project_cli: PathBuf,
    pub replay_policy: PathBuf,
    pub replay_startup_timeout: Duration,
    pub pr_base: String,
    pub recorder_config: Option<PathBuf>,
    pub recording_rule: Option<String>,
    pub api_verification: ApiVerificationConfig,
    pub runner_owned_response_assertions: bool,
}

#[derive(Debug, Clone)]
pub(super) struct RunLayout {
    pub target_root: PathBuf,
    pub run_key: String,
    pub case_source: PathBuf,
    pub progress_path: PathBuf,
    pub local_root: PathBuf,
    pub current_path: PathBuf,
    pub run_root: PathBuf,
    pub index_path: PathBuf,
    pub group_index_path: PathBuf,
    pub active_dir: PathBuf,
    pub latest_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RunStatus {
    Running,
    Finalizing,
    Successful,
    Failed,
    Interrupted,
}

impl RunStatus {
    pub(super) fn is_terminal(self) -> bool {
        matches!(self, Self::Successful | Self::Failed | Self::Interrupted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CaseStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseExecution {
    pub case_id: String,
    pub case_dir: PathBuf,
    pub group_id: String,
    pub status: CaseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_clean: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_assertion: Option<ResponseAssertionCaseReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ApiExecution {
    pub api_key: String,
    pub group_id: String,
    pub method: String,
    pub api_pattern: String,
    pub case_ids: Vec<String>,
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub incomplete: u32,
    pub successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensure_status: Option<String>,
    pub report_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ActiveRunState {
    pub version: u32,
    pub run_key: String,
    pub sequence: u64,
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    pub case_source: PathBuf,
    pub source_revision: String,
    pub case_inventory_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_rule: Option<String>,
    pub replay_session: PathBuf,
    pub replay_report: PathBuf,
    pub aggregate_report: PathBuf,
    pub assertions_report: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_pid: Option<u32>,
    #[serde(default)]
    pub target_started: bool,
    pub replay_finalized: bool,
    pub aggregate_complete: bool,
    pub aggregate_clean: bool,
    pub cases: Vec<CaseExecution>,
    pub apis: Vec<ApiExecution>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl ActiveRunState {
    pub(super) fn new(
        run_key: String,
        sequence: u64,
        inventory: &CaseGroupInventory,
        recording_rule: Option<String>,
        active_dir: &std::path::Path,
    ) -> Self {
        let mut cases = inventory
            .groups
            .iter()
            .flat_map(|group| {
                group.cases.iter().map(|case| {
                    (
                        case.recorded_at,
                        CaseExecution {
                            case_id: case.case_id.clone(),
                            case_dir: case.case_dir.clone(),
                            group_id: group.group_id.clone(),
                            status: CaseStatus::Pending,
                            assertion_passed: None,
                            replay_clean: None,
                            response_assertion: None,
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        cases.sort_by(|(left_time, left), (right_time, right)| {
            left_time
                .cmp(right_time)
                .then_with(|| left.case_id.cmp(&right.case_id))
        });
        let cases = cases.into_iter().map(|(_, execution)| execution).collect();
        let reports = active_dir.join("reports");
        Self {
            version: STATE_VERSION,
            run_key,
            sequence,
            status: RunStatus::Running,
            started_at: Utc::now(),
            finished_at: None,
            case_source: inventory.case_source.clone(),
            source_revision: inventory.source_revision.clone(),
            case_inventory_id: inventory.case_inventory_id.clone(),
            recording_rule,
            replay_session: active_dir.join("tmp/session.json"),
            replay_report: reports.join("replay-report.json"),
            aggregate_report: reports.join("aggregate.json"),
            assertions_report: reports.join("assertions.json"),
            session_id: None,
            replay_pid: None,
            target_started: false,
            replay_finalized: false,
            aggregate_complete: false,
            aggregate_clean: false,
            cases,
            apis: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ApiProgress {
    pub cases: u32,
    #[serde(default, skip_serializing)]
    pub status: String,
    #[serde(default)]
    pub executions: u64,
    #[serde(default)]
    pub successful: u64,
    #[serde(default)]
    pub consecutive_successful_runs: u64,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default)]
    pub successful_cases: u64,
    #[serde(default)]
    pub consecutive_successful_cases: u64,
    #[serde(default)]
    pub verified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ApiRunContribution {
    #[serde(default)]
    pub counted: bool,
    #[serde(default)]
    pub successful: bool,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default)]
    pub successful_cases: u64,
    #[serde(default)]
    pub baseline_consecutive_successful_runs: u64,
    #[serde(default)]
    pub baseline_consecutive_successful_cases: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct RunContribution {
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub counted: bool,
    #[serde(default)]
    pub successful: bool,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default)]
    pub successful_cases: u64,
    #[serde(default)]
    pub baseline_consecutive_successful_runs: u64,
    #[serde(default)]
    pub baseline_consecutive_successful_cases: u64,
    #[serde(default)]
    pub api_keys: BTreeSet<String>,
    #[serde(default)]
    pub apis: BTreeMap<String, ApiRunContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunIndex {
    pub version: u32,
    pub run_key: String,
    pub case_source: PathBuf,
    #[serde(default)]
    pub source_revision: String,
    #[serde(default)]
    pub case_inventory_id: String,
    #[serde(default)]
    pub inventory_complete: bool,
    pub executions: u64,
    pub successful: u64,
    pub replayed_cases: u64,
    pub passed_cases: u64,
    #[serde(default)]
    pub consecutive_successful_runs: u64,
    #[serde(default)]
    pub consecutive_successful_cases: u64,
    #[serde(default)]
    pub apis: BTreeMap<String, ApiProgress>,
    #[serde(default)]
    pub current_run: RunContribution,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub latest_focused_sequences: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_status: Option<RunStatus>,
}

impl RunIndex {
    pub(super) fn empty(run_key: String, case_source: PathBuf) -> Self {
        Self {
            version: STATE_VERSION,
            run_key,
            case_source,
            source_revision: String::new(),
            case_inventory_id: String::new(),
            inventory_complete: false,
            executions: 0,
            successful: 0,
            replayed_cases: 0,
            passed_cases: 0,
            consecutive_successful_runs: 0,
            consecutive_successful_cases: 0,
            apis: BTreeMap::new(),
            current_run: RunContribution {
                initialized: true,
                ..RunContribution::default()
            },
            latest_focused_sequences: BTreeMap::new(),
            latest_sequence: None,
            latest_status: None,
        }
    }

    pub(super) fn normalize_legacy_progress(&mut self) {
        if self.current_run.initialized {
            return;
        }
        if !self.inventory_complete && self.latest_sequence.is_some() {
            self.inventory_complete = true;
        }
        let had_execution = self.executions > 0;
        let api_keys = self.apis.keys().cloned().collect::<BTreeSet<_>>();
        let mut executed_cases = 0_u64;
        let mut successful_cases = 0_u64;
        let mut all_current_apis_successful = !api_keys.is_empty();
        for api in self.apis.values_mut() {
            let counted = api.executions > 0 || !api.status.is_empty();
            let successful = counted
                && (api.consecutive_successful_runs > 0
                    || (api.status == "verified"
                        && self.latest_status == Some(RunStatus::Successful)));
            let current_executed_cases = if counted { u64::from(api.cases) } else { 0 };
            let current_successful_cases = if successful { u64::from(api.cases) } else { 0 };
            if counted {
                api.executions = 1;
                api.successful = u64::from(successful);
                api.executed_cases = current_executed_cases;
                api.successful_cases = current_successful_cases;
                api.consecutive_successful_runs = u64::from(successful);
                api.consecutive_successful_cases = current_successful_cases;
            }
            api.verified = false;
            api.status.clear();
            executed_cases = executed_cases.saturating_add(current_executed_cases);
            successful_cases = successful_cases.saturating_add(current_successful_cases);
            all_current_apis_successful &= successful;
        }
        let successful = had_execution && self.inventory_complete && all_current_apis_successful;
        self.executions = u64::from(had_execution);
        self.successful = u64::from(successful);
        self.replayed_cases = executed_cases;
        self.passed_cases = successful_cases;
        self.consecutive_successful_runs = u64::from(successful);
        self.consecutive_successful_cases = if successful { successful_cases } else { 0 };
        self.current_run = RunContribution {
            initialized: true,
            counted: had_execution,
            successful,
            executed_cases,
            successful_cases,
            baseline_consecutive_successful_runs: 0,
            baseline_consecutive_successful_cases: 0,
            api_keys,
            apis: self
                .apis
                .iter()
                .map(|(api_key, api)| {
                    (
                        api_key.clone(),
                        ApiRunContribution {
                            counted: api.executions > 0,
                            successful: api.successful > 0,
                            executed_cases: api.executed_cases,
                            successful_cases: api.successful_cases,
                            baseline_consecutive_successful_runs: 0,
                            baseline_consecutive_successful_cases: 0,
                        },
                    )
                })
                .collect(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup};

    #[test]
    fn active_run_orders_cases_globally_by_recording_timestamp() {
        let inventory = CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![
                CanonicalCaseGroup {
                    group_id: "GET /later".to_string(),
                    method: "GET".to_string(),
                    source_route: "/later".to_string(),
                    pattern: None,
                    case_inventory_id: "later".to_string(),
                    cases: vec![canonical_case("case-a", "2026-07-24T02:00:02Z")],
                },
                CanonicalCaseGroup {
                    group_id: "GET /earlier".to_string(),
                    method: "GET".to_string(),
                    source_route: "/earlier".to_string(),
                    pattern: None,
                    case_inventory_id: "earlier".to_string(),
                    cases: vec![canonical_case("case-z", "2026-07-24T02:00:01Z")],
                },
            ],
        };

        let state = ActiveRunState::new(
            "run".to_string(),
            1,
            &inventory,
            None,
            std::path::Path::new("/run"),
        );

        assert_eq!(
            state
                .cases
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<Vec<_>>(),
            ["case-z", "case-a"]
        );
    }

    fn canonical_case(case_id: &str, recorded_at: &str) -> CanonicalCase {
        CanonicalCase {
            case_id: case_id.to_string(),
            case_dir: PathBuf::from("/cases").join(case_id),
            recorded_at: Some(recorded_at.parse().unwrap()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AssertionCase {
    pub case_id: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseAssertionCaseReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AssertionReport {
    pub version: u32,
    pub case_source: String,
    pub expected_response: String,
    pub assertion_mode: String,
    pub source_revision: String,
    pub case_inventory_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_fingerprint: Option<String>,
    pub cases: Vec<AssertionCase>,
}

impl AssertionReport {
    pub(super) fn new(state: &ActiveRunState, runner_owned: bool) -> Self {
        let policy = state
            .cases
            .iter()
            .find_map(|case| case.response_assertion.as_ref());
        Self {
            version: ASSERTION_REPORT_VERSION,
            case_source: state.case_source.display().to_string(),
            expected_response: "assertions_only".to_string(),
            assertion_mode: if runner_owned {
                "runner_owned".to_string()
            } else {
                "target_owned_legacy".to_string()
            },
            source_revision: state.source_revision.clone(),
            case_inventory_id: state.case_inventory_id.clone(),
            policy_path: policy.map(|report| report.policy_path.clone()),
            policy_fingerprint: policy.map(|report| report.policy_fingerprint.clone()),
            cases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CurrentPointer {
    pub version: u32,
    pub current_run: String,
    pub current_run_state: PathBuf,
    pub status: RunStatus,
}
