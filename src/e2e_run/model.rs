use std::collections::BTreeMap;
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
        let cases = inventory
            .groups
            .iter()
            .flat_map(|group| {
                group.cases.iter().map(|case| CaseExecution {
                    case_id: case.case_id.clone(),
                    case_dir: case.case_dir.clone(),
                    group_id: group.group_id.clone(),
                    status: CaseStatus::Pending,
                    assertion_passed: None,
                    replay_clean: None,
                    response_assertion: None,
                })
            })
            .collect();
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
    pub failed: u64,
    pub interrupted: u64,
    pub replayed_cases: u64,
    pub passed_cases: u64,
    pub failed_cases: u64,
    pub incomplete_cases: u64,
    #[serde(default)]
    pub consecutive_successful_runs: u64,
    #[serde(default)]
    pub consecutive_successful_cases: u64,
    #[serde(default)]
    pub apis: BTreeMap<String, ApiProgress>,
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
            failed: 0,
            interrupted: 0,
            replayed_cases: 0,
            passed_cases: 0,
            failed_cases: 0,
            incomplete_cases: 0,
            consecutive_successful_runs: 0,
            consecutive_successful_cases: 0,
            apis: BTreeMap::new(),
            latest_focused_sequences: BTreeMap::new(),
            latest_sequence: None,
            latest_status: None,
        }
    }

    pub(super) fn normalize_legacy_progress(&mut self) {
        if !self.inventory_complete && self.latest_sequence.is_some() {
            self.inventory_complete = true;
        }
        let latest_successful = self.latest_status == Some(RunStatus::Successful);
        let legacy_current_cases = self
            .apis
            .values()
            .filter(|api| api.executions == 0)
            .map(|api| u64::from(api.cases))
            .sum::<u64>();
        if latest_successful && self.consecutive_successful_runs == 0 {
            self.consecutive_successful_runs = 1;
            if self.consecutive_successful_cases == 0 {
                self.consecutive_successful_cases = legacy_current_cases;
            }
        }
        for api in self.apis.values_mut() {
            if api.executions > 0 || api.status.is_empty() {
                continue;
            }
            api.executions = self.executions;
            if api.status == "verified" {
                api.successful = self.successful;
                api.successful_cases = u64::from(api.cases).saturating_mul(api.successful);
                if latest_successful {
                    api.consecutive_successful_runs = 1;
                    api.consecutive_successful_cases = u64::from(api.cases);
                }
            }
            api.executed_cases = u64::from(api.cases).saturating_mul(api.executions);
            api.status.clear();
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
