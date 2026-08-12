use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_STATE_ERRORS: usize = 128;
const MAX_STATE_ERROR_BYTES: usize = 2_048;
const STATE_ERROR_OVERFLOW: &str =
    "additional internal errors omitted; use the bounded terminal diagnosis";

use crate::case_group::CaseGroupInventory;
use crate::replay::ResponseDifference;

pub(super) const STATE_VERSION: u32 = 2;
pub(super) const ASSERTION_REPORT_VERSION: u32 = 2;
pub(super) const DEFAULT_REPLAY_STARTUP_TIMEOUT_SECONDS: u64 = 60;
pub(super) const DEFAULT_TARGET_STARTUP_TIMEOUT_SECONDS: u64 = 60;
pub(super) const DEFAULT_TARGET_REQUEST_TIMEOUT_SECONDS: u64 = 30;
pub(super) const MAX_RESPONSE_DIFFERENCE_INDEX: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectConfig {
    pub version: u32,
    pub source: SourceProjectConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breeze: Option<BreezeProjectConfig>,
    pub target: TargetProjectConfig,
    pub replay: ReplayProjectConfig,
    pub recording: RecordingProjectConfig,
    pub delivery: DeliveryProjectConfig,
    pub state: StateProjectConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceProjectConfig {
    pub container: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BreezeProjectConfig {
    pub container: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetProjectConfig {
    pub dockerfile: PathBuf,
    pub startup: crate::startup::StartupConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_gates: Option<Vec<TargetQualityGateConfig>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetQualityGateConfig {
    pub name: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplayProjectConfig {
    pub policy: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordingProjectConfig {
    pub config: PathBuf,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryProjectConfig {
    pub pr_base: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateProjectConfig {
    #[serde(default = "default_runtime_root")]
    pub runtime_root: PathBuf,
}

fn default_runtime_root() -> PathBuf {
    PathBuf::from(crate::internal_runtime::PROJECT_RELATIVE_ROOT)
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedProjectConfig {
    pub(crate) target_dockerfile: PathBuf,
    pub(crate) target_startup: crate::startup::StartupConfig,
    pub(crate) target_http_origin: String,
    pub(crate) target_port: u16,
    pub(crate) target_motan_upstream: Option<String>,
    pub(crate) target_readiness_path: String,
    pub(crate) target_readiness_status: u16,
    pub(crate) target_startup_timeout: Duration,
    pub(crate) target_request_timeout: Duration,
    pub(crate) target_quality_gates: Vec<TargetQualityGateConfig>,
    pub(crate) target_max_response_bytes: usize,
    pub(crate) source_container: String,
    pub(crate) breeze_container: Option<String>,
    pub(crate) replay_policy: PathBuf,
    pub(crate) replay_startup_timeout: Duration,
    pub(crate) pr_base: String,
    pub(crate) recorder_config: PathBuf,
    pub(crate) recording_rule: String,
    pub(crate) runner_owned_response_assertions: bool,
}

#[derive(Debug, Clone)]
pub(super) struct RunLayout {
    pub target_root: PathBuf,
    pub run_key: String,
    pub case_source: PathBuf,
    pub progress_path: PathBuf,
    pub legacy_progress_path: PathBuf,
    pub internal_root: PathBuf,
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
    pub response_assertion: Option<ResponseAssertionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ResponseAssertionSummary {
    pub passed: bool,
    pub difference_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub difference_index: Vec<ResponseDifference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_difference: Option<ResponseDifference>,
    pub detail_report: PathBuf,
    pub detail_fingerprint: String,
    pub expected_response: PathBuf,
    pub actual_response: PathBuf,
    pub policy_path: String,
    pub policy_fingerprint: String,
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
    pub complete_pass: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_container_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_anchor_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_image_id: Option<String>,
    pub replay_finalized: bool,
    pub aggregate_complete: bool,
    pub aggregate_clean: bool,
    pub cases: Vec<CaseExecution>,
    pub apis: Vec<ApiExecution>,
    #[serde(default, deserialize_with = "deserialize_state_errors")]
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
            target_container_name: None,
            target_anchor_name: None,
            target_image_id: None,
            replay_finalized: false,
            aggregate_complete: false,
            aggregate_clean: false,
            cases,
            apis: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub(super) fn push_error(&mut self, error: impl Into<String>) {
        push_bounded_state_error(&mut self.errors, error.into());
    }
}

fn deserialize_state_errors<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let errors = Vec::<String>::deserialize(deserializer)?;
    let mut bounded = Vec::with_capacity(errors.len().min(MAX_STATE_ERRORS));
    for error in errors {
        push_bounded_state_error(&mut bounded, error);
    }
    Ok(bounded)
}

fn push_bounded_state_error(errors: &mut Vec<String>, error: String) {
    if errors.len() < MAX_STATE_ERRORS.saturating_sub(1) {
        errors.push(bound_state_error(error));
        return;
    }
    if errors.last().map(String::as_str) != Some(STATE_ERROR_OVERFLOW) {
        errors.truncate(MAX_STATE_ERRORS.saturating_sub(1));
        errors.push(STATE_ERROR_OVERFLOW.to_owned());
    }
}

fn bound_state_error(mut error: String) -> String {
    if error.len() <= MAX_STATE_ERROR_BYTES {
        return error;
    }
    let suffix = format!("… [truncated; original_bytes={}]", error.len());
    let mut end = MAX_STATE_ERROR_BYTES.saturating_sub(suffix.len());
    while !error.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    error.truncate(end);
    error.push_str(&suffix);
    error
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ApiProgress {
    pub cases: u32,
    #[serde(default, skip_serializing)]
    pub status: String,
    #[serde(default)]
    pub executions: u64,
    #[serde(default, alias = "successful")]
    pub passed_runs: u64,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default, alias = "successful_cases")]
    pub passed_cases: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ApiRunContribution {
    #[serde(default)]
    pub counted: bool,
    #[serde(default, alias = "successful")]
    pub passed: bool,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default, alias = "successful_cases")]
    pub passed_cases: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct RunContribution {
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub counted: bool,
    #[serde(default, alias = "successful")]
    pub passed: bool,
    #[serde(default)]
    pub executed_cases: u64,
    #[serde(default, alias = "successful_cases")]
    pub passed_cases: u64,
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
    #[serde(alias = "successful")]
    pub passed_runs: u64,
    pub replayed_cases: u64,
    #[serde(alias = "successful_cases")]
    pub passed_cases: u64,
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
            passed_runs: 0,
            replayed_cases: 0,
            passed_cases: 0,
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

    #[test]
    fn active_run_bounds_persisted_errors() {
        let mut state = ActiveRunState::new(
            "run".to_string(),
            1,
            &CaseGroupInventory {
                case_source: PathBuf::from("/cases"),
                source_revision: "source".to_string(),
                case_inventory_id: "inventory".to_string(),
                groups: Vec::new(),
            },
            None,
            std::path::Path::new("/run"),
        );

        state.push_error("界".repeat(MAX_STATE_ERROR_BYTES));
        for index in 0..MAX_STATE_ERRORS {
            state.push_error(format!("error {index}"));
        }

        assert_eq!(state.errors.len(), MAX_STATE_ERRORS);
        assert!(state.errors[0].len() <= MAX_STATE_ERROR_BYTES);
        assert_eq!(state.errors.last().unwrap(), STATE_ERROR_OVERFLOW);

        state.errors = (0..MAX_STATE_ERRORS + 1)
            .map(|_| "界".repeat(MAX_STATE_ERROR_BYTES))
            .collect();
        let restored: ActiveRunState =
            serde_yaml::from_str(&serde_yaml::to_string(&state).unwrap()).unwrap();
        assert_eq!(restored.errors.len(), MAX_STATE_ERRORS);
        assert!(restored.errors[0].len() <= MAX_STATE_ERROR_BYTES);
        assert_eq!(restored.errors.last().unwrap(), STATE_ERROR_OVERFLOW);
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
    pub response: Option<ResponseAssertionSummary>,
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
