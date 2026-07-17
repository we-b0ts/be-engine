use std::collections::BTreeMap;

use serde::Serialize;

use super::model::{
    ActiveRunState, ApiExecution, ApiProgress, CaseStatus, RunIndex, RunStatus, STATE_VERSION,
};

#[derive(Debug, Clone, Serialize)]
pub(super) struct ProgressReport {
    version: u32,
    updated_at: String,
    status: String,
    run: ProgressRun,
    progress: ProgressSummary,
    latest_run: LatestRun,
    apis: BTreeMap<String, ProgressApi>,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressRun {
    key: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressSummary {
    runs: RunCounts,
    cases: CaseCounts,
    apis: ApiCounts,
}

#[derive(Debug, Clone, Serialize)]
struct RunCounts {
    total: u64,
    successful: u64,
    failed: u64,
    interrupted: u64,
    consecutive_successful: u32,
    required_consecutive_successful: u32,
}

#[derive(Debug, Clone, Serialize)]
struct CaseCounts {
    total: u32,
    replayed: u64,
    passed: u64,
    failed: u64,
    incomplete: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ApiCounts {
    total: u32,
    verified: u32,
    pending: u32,
}

#[derive(Debug, Clone, Serialize)]
struct LatestRun {
    number: u64,
    status: RunStatus,
    cases: LatestCaseCounts,
    apis: LatestApiCounts,
    consecutive_successful: u32,
    highlights: Highlights,
}

#[derive(Debug, Clone, Serialize)]
struct LatestCaseCounts {
    total: u32,
    passed: u32,
    failed: u32,
    incomplete: u32,
}

#[derive(Debug, Clone, Serialize)]
struct LatestApiCounts {
    total: u32,
    passed: u32,
    failed: u32,
    incomplete: u32,
}

#[derive(Debug, Clone, Serialize)]
struct Highlights {
    #[serde(skip_serializing_if = "Option::is_none")]
    most_failed_cases: Option<ApiHighlight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    highest_failure_rate: Option<ApiHighlight>,
}

#[derive(Debug, Clone, Serialize)]
struct ApiHighlight {
    api: String,
    failed: u32,
    total: u32,
    failure_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressApi {
    cases: u32,
    status: String,
    consecutive_successful: u32,
    required_consecutive_successful: u32,
}

pub(super) fn update_index(index: &mut RunIndex, state: &ActiveRunState) {
    if index.latest_sequence == Some(state.sequence) {
        return;
    }
    let baseline_changed = (!index.source_revision.is_empty()
        && index.source_revision != state.source_revision)
        || (!index.case_inventory_id.is_empty()
            && index.case_inventory_id != state.case_inventory_id);
    if baseline_changed {
        index.consecutive_successful = 0;
        for api in index.apis.values_mut() {
            api.consecutive_successful = 0;
            api.status = "pending".to_string();
        }
    }
    index.source_revision = state.source_revision.clone();
    index.case_inventory_id = state.case_inventory_id.clone();
    index.executions += 1;
    index.latest_sequence = Some(state.sequence);
    index.latest_status = Some(state.status);
    match state.status {
        RunStatus::Successful => {
            index.successful += 1;
            index.consecutive_successful += 1;
        }
        RunStatus::Failed => {
            index.failed += 1;
            index.consecutive_successful = 0;
        }
        RunStatus::Interrupted => {
            index.interrupted += 1;
            index.consecutive_successful = 0;
        }
        RunStatus::Running | RunStatus::Finalizing => {}
    }

    for case in &state.cases {
        if case.status != CaseStatus::Pending {
            index.replayed_cases += 1;
        }
        match case.status {
            CaseStatus::Passed => index.passed_cases += 1,
            CaseStatus::Failed => index.failed_cases += 1,
            CaseStatus::Incomplete | CaseStatus::Pending | CaseStatus::Running => {
                index.incomplete_cases += 1;
            }
        }
    }

    let global_evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    let current_api_keys = state
        .apis
        .iter()
        .map(|api| api.api_key.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    index
        .apis
        .retain(|api_key, _| current_api_keys.contains(api_key.as_str()));
    for api in &state.apis {
        let progress = index
            .apis
            .entry(api.api_key.clone())
            .or_insert(ApiProgress {
                cases: api.total,
                status: "pending".to_string(),
                consecutive_successful: 0,
                required_consecutive_successful: index.required_consecutive_successful,
            });
        progress.cases = api.total;
        progress.required_consecutive_successful = index.required_consecutive_successful;
        if state.status != RunStatus::Interrupted && global_evidence_clean && api.successful {
            progress.consecutive_successful += 1;
        } else {
            progress.consecutive_successful = 0;
        }
        progress.status =
            if progress.consecutive_successful >= progress.required_consecutive_successful {
                "verified"
            } else if !api.successful {
                "needs_attention"
            } else {
                "pending"
            }
            .to_string();
    }
}

pub(super) fn build_progress(index: &RunIndex, state: &ActiveRunState) -> ProgressReport {
    let total_cases = state.cases.len() as u32;
    let passed_cases = count_cases(state, CaseStatus::Passed);
    let failed_cases = count_cases(state, CaseStatus::Failed);
    let incomplete_cases = total_cases - passed_cases - failed_cases;
    let passed_apis = state.apis.iter().filter(|api| api.successful).count() as u32;
    let failed_apis = state.apis.iter().filter(|api| api.failed > 0).count() as u32;
    let incomplete_apis = state
        .apis
        .iter()
        .filter(|api| !api.successful && api.failed == 0)
        .count() as u32;
    let verified = index
        .apis
        .values()
        .filter(|api| api.status == "verified")
        .count() as u32;
    let complete = verified == state.apis.len() as u32
        && index.consecutive_successful >= index.required_consecutive_successful;
    let status = if complete {
        "complete"
    } else if state.status == RunStatus::Successful {
        "in_progress"
    } else {
        "needs_attention"
    };

    ProgressReport {
        version: STATE_VERSION,
        updated_at: state
            .finished_at
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
        status: status.to_string(),
        run: ProgressRun {
            key: state.run_key.clone(),
        },
        progress: ProgressSummary {
            runs: RunCounts {
                total: index.executions,
                successful: index.successful,
                failed: index.failed,
                interrupted: index.interrupted,
                consecutive_successful: index.consecutive_successful,
                required_consecutive_successful: index.required_consecutive_successful,
            },
            cases: CaseCounts {
                total: total_cases,
                replayed: index.replayed_cases,
                passed: index.passed_cases,
                failed: index.failed_cases,
                incomplete: index.incomplete_cases,
            },
            apis: ApiCounts {
                total: state.apis.len() as u32,
                verified,
                pending: state.apis.len() as u32 - verified,
            },
        },
        latest_run: LatestRun {
            number: state.sequence,
            status: state.status,
            cases: LatestCaseCounts {
                total: total_cases,
                passed: passed_cases,
                failed: failed_cases,
                incomplete: incomplete_cases,
            },
            apis: LatestApiCounts {
                total: state.apis.len() as u32,
                passed: passed_apis,
                failed: failed_apis,
                incomplete: incomplete_apis,
            },
            consecutive_successful: index.consecutive_successful,
            highlights: highlights(&state.apis),
        },
        apis: index
            .apis
            .iter()
            .map(|(api_key, api)| {
                (
                    api_key.clone(),
                    ProgressApi {
                        cases: api.cases,
                        status: api.status.clone(),
                        consecutive_successful: api.consecutive_successful,
                        required_consecutive_successful: api.required_consecutive_successful,
                    },
                )
            })
            .collect(),
    }
}

fn count_cases(state: &ActiveRunState, status: CaseStatus) -> u32 {
    state
        .cases
        .iter()
        .filter(|case| case.status == status)
        .count() as u32
}

fn highlights(apis: &[ApiExecution]) -> Highlights {
    let failing = apis.iter().filter(|api| api.failed > 0).collect::<Vec<_>>();
    let most_failed_cases = failing
        .iter()
        .copied()
        .max_by_key(|api| (api.failed, std::cmp::Reverse(api.api_key.as_str())))
        .map(highlight);
    let highest_failure_rate = failing
        .iter()
        .copied()
        .max_by(|left, right| {
            failure_rate(left)
                .total_cmp(&failure_rate(right))
                .then_with(|| right.api_key.cmp(&left.api_key))
        })
        .map(highlight);
    Highlights {
        most_failed_cases,
        highest_failure_rate,
    }
}

fn highlight(api: &ApiExecution) -> ApiHighlight {
    ApiHighlight {
        api: api.api_key.clone(),
        failed: api.failed,
        total: api.total,
        failure_rate: failure_rate(api),
    }
}

fn failure_rate(api: &ApiExecution) -> f64 {
    if api.total == 0 {
        0.0
    } else {
        (f64::from(api.failed) * 10_000.0 / f64::from(api.total)).round() / 100.0
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::e2e_run::model::{ActiveRunState, ApiExecution, CaseExecution};

    fn state(api_passed: u32, api_failed: u32, status: RunStatus) -> ActiveRunState {
        let cases = (0..api_passed)
            .map(|index| CaseExecution {
                case_id: format!("passed-{index}"),
                case_dir: PathBuf::from("/cases"),
                group_id: "GET /api/orders/*".to_string(),
                status: CaseStatus::Passed,
                assertion_passed: Some(true),
                replay_clean: Some(true),
            })
            .chain((0..api_failed).map(|index| CaseExecution {
                case_id: format!("failed-{index}"),
                case_dir: PathBuf::from("/cases"),
                group_id: "GET /api/orders/*".to_string(),
                status: CaseStatus::Failed,
                assertion_passed: Some(false),
                replay_clean: Some(true),
            }))
            .collect::<Vec<_>>();
        ActiveRunState {
            version: STATE_VERSION,
            run_key: "run".to_string(),
            sequence: 1,
            status,
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            recording_rule: Some("record-api".to_string()),
            required_consecutive_successful_runs: 3,
            replay_session: PathBuf::from("/session"),
            replay_report: PathBuf::from("/report"),
            aggregate_report: PathBuf::from("/aggregate"),
            assertions_report: PathBuf::from("/assertions"),
            session_id: Some("session".to_string()),
            replay_pid: None,
            target_started: false,
            replay_finalized: true,
            aggregate_complete: true,
            aggregate_clean: true,
            cases,
            apis: vec![ApiExecution {
                api_key: "GET /api/orders/*".to_string(),
                group_id: "GET /api/orders/*".to_string(),
                method: "GET".to_string(),
                api_pattern: "/api/orders/*".to_string(),
                case_ids: Vec::new(),
                total: api_passed + api_failed,
                passed: api_passed,
                failed: api_failed,
                incomplete: 0,
                successful: api_failed == 0,
                ensure_status: None,
                report_dir: PathBuf::from("apis/api-0001"),
            }],
            errors: Vec::new(),
        }
    }

    #[test]
    fn partial_api_success_resets_its_run_streak() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"), 3);
        let passed = state(30, 0, RunStatus::Successful);
        update_index(&mut index, &passed);
        let mut passed_again = passed.clone();
        passed_again.sequence = 2;
        update_index(&mut index, &passed_again);
        assert_eq!(index.apis["GET /api/orders/*"].consecutive_successful, 2);

        let mut failed = state(29, 1, RunStatus::Failed);
        failed.sequence = 3;
        update_index(&mut index, &failed);
        assert_eq!(index.consecutive_successful, 0);
        assert_eq!(index.apis["GET /api/orders/*"].consecutive_successful, 0);
    }

    #[test]
    fn highlights_report_largest_count_and_rate() {
        let mut first = state(29, 1, RunStatus::Failed);
        first.apis.push(ApiExecution {
            api_key: "POST /api/payments".to_string(),
            group_id: "POST /api/payments".to_string(),
            method: "POST".to_string(),
            api_pattern: "/api/payments".to_string(),
            case_ids: Vec::new(),
            total: 4,
            passed: 2,
            failed: 2,
            incomplete: 0,
            successful: false,
            ensure_status: None,
            report_dir: PathBuf::from("apis/api-0002"),
        });
        let highlights = highlights(&first.apis);
        assert_eq!(
            highlights.most_failed_cases.unwrap().api,
            "POST /api/payments"
        );
        assert_eq!(highlights.highest_failure_rate.unwrap().failure_rate, 50.0);
    }

    #[test]
    fn interrupted_run_resets_api_and_global_streaks() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"), 3);
        let first = state(30, 0, RunStatus::Successful);
        update_index(&mut index, &first);
        assert_eq!(index.consecutive_successful, 1);
        assert_eq!(index.apis["GET /api/orders/*"].consecutive_successful, 1);

        let mut interrupted = state(30, 0, RunStatus::Interrupted);
        interrupted.sequence = 2;
        update_index(&mut index, &interrupted);
        assert_eq!(index.consecutive_successful, 0);
        assert_eq!(index.apis["GET /api/orders/*"].consecutive_successful, 0);
    }

    #[test]
    fn publishing_same_sequence_is_idempotent() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"), 3);
        let completed = state(30, 0, RunStatus::Successful);
        update_index(&mut index, &completed);
        update_index(&mut index, &completed);
        assert_eq!(index.executions, 1);
        assert_eq!(index.replayed_cases, 30);
        assert_eq!(index.consecutive_successful, 1);
    }

    #[test]
    fn one_api_can_advance_when_another_has_only_assertion_failures() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"), 3);
        let mut round = state(30, 0, RunStatus::Failed);
        round.apis.push(ApiExecution {
            api_key: "POST /api/payments".to_string(),
            group_id: "POST /api/payments".to_string(),
            method: "POST".to_string(),
            api_pattern: "/api/payments".to_string(),
            case_ids: vec!["payment-failed".to_string()],
            total: 1,
            passed: 0,
            failed: 1,
            incomplete: 0,
            successful: false,
            ensure_status: None,
            report_dir: PathBuf::from("apis/api-0002"),
        });
        update_index(&mut index, &round);
        assert_eq!(index.consecutive_successful, 0);
        assert_eq!(index.apis["GET /api/orders/*"].consecutive_successful, 1);
        assert_eq!(index.apis["POST /api/payments"].consecutive_successful, 0);
    }

    #[test]
    fn human_progress_omits_protocol_evidence() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"), 3);
        let completed = state(30, 0, RunStatus::Successful);
        update_index(&mut index, &completed);
        let yaml = serde_yaml::to_string(&build_progress(&index, &completed)).unwrap();
        assert!(!yaml.contains("connection"));
        assert!(!yaml.contains("aggregate"));
        assert!(!yaml.contains("policy"));
        assert!(!yaml.contains("session"));
        assert!(!yaml.contains("protocol"));
        assert!(!yaml.contains("/cases"));
    }
}
