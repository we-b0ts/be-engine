use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::model::{
    ActiveRunState, ApiExecution, ApiProgress, ApiVerificationConfig, CaseStatus, RunIndex,
    RunStatus, STATE_VERSION,
};
use crate::case_group::CaseGroupInventory;

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
    runs: SuccessCounts,
    cases: SuccessCounts,
    apis: ApiCounts,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct SuccessCounts {
    executed: u64,
    successful: u64,
    consecutive_successful: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ApiCounts {
    total: u32,
    verified: u32,
}

#[derive(Debug, Clone, Serialize)]
struct LatestRun {
    number: u64,
    successful: bool,
    cases: LatestCounts,
    apis: LatestCounts,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct LatestCounts {
    executed: u32,
    successful: u32,
}

#[derive(Debug, Clone, Serialize)]
struct ProgressApi {
    verified: bool,
    runs: SuccessCounts,
    cases: SuccessCounts,
}

pub(super) fn update_index(
    index: &mut RunIndex,
    state: &ActiveRunState,
    verification: &ApiVerificationConfig,
) {
    if index.latest_sequence == Some(state.sequence) {
        return;
    }
    reconcile_baseline(index, state);
    index.inventory_complete = true;
    update_execution_totals(index, state);
    index.latest_sequence = Some(state.sequence);

    let global_evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    let current_api_keys = state
        .apis
        .iter()
        .map(|api| api.api_key.as_str())
        .collect::<BTreeSet<_>>();
    index
        .apis
        .retain(|api_key, _| current_api_keys.contains(api_key.as_str()));
    for api in &state.apis {
        let progress = index.apis.entry(api.api_key.clone()).or_default();
        update_api_progress(progress, state, api, global_evidence_clean);
    }
    refresh_verification(index, verification);
}

pub(super) fn update_focused_index(
    index: &mut RunIndex,
    state: &ActiveRunState,
    inventory: &CaseGroupInventory,
    inventory_complete: bool,
    verification: &ApiVerificationConfig,
) {
    let Some(api) = state.apis.first() else {
        return;
    };
    if index.latest_focused_sequences.get(&api.api_key) == Some(&state.sequence) {
        return;
    }
    reconcile_baseline(index, state);
    index.inventory_complete = inventory_complete;
    update_execution_totals(index, state);
    index
        .latest_focused_sequences
        .insert(api.api_key.clone(), state.sequence);

    let current_apis = inventory
        .groups
        .iter()
        .map(|group| {
            let pattern = group
                .pattern
                .clone()
                .unwrap_or_else(|| group.source_route.clone());
            (
                format!("{} {pattern}", group.method),
                group.cases.len() as u32,
            )
        })
        .collect::<BTreeMap<_, _>>();
    index
        .apis
        .retain(|api_key, _| current_apis.contains_key(api_key));
    for (api_key, cases) in current_apis {
        index.apis.entry(api_key).or_default().cases = cases;
    }
    let global_evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    let progress = index.apis.entry(api.api_key.clone()).or_default();
    update_api_progress(progress, state, api, global_evidence_clean);
    refresh_verification(index, verification);
}

fn reconcile_baseline(index: &mut RunIndex, state: &ActiveRunState) {
    let baseline_changed = (!index.source_revision.is_empty()
        && index.source_revision != state.source_revision)
        || (!index.case_inventory_id.is_empty()
            && index.case_inventory_id != state.case_inventory_id);
    if baseline_changed {
        index.consecutive_successful_runs = 0;
        index.consecutive_successful_cases = 0;
        for api in index.apis.values_mut() {
            api.consecutive_successful_runs = 0;
            api.consecutive_successful_cases = 0;
            api.verified = false;
        }
        index.latest_focused_sequences.clear();
    }
    index.source_revision = state.source_revision.clone();
    index.case_inventory_id = state.case_inventory_id.clone();
}

fn update_execution_totals(index: &mut RunIndex, state: &ActiveRunState) {
    index.executions += 1;
    index.latest_status = Some(state.status);
    match state.status {
        RunStatus::Successful => {
            index.successful += 1;
            index.consecutive_successful_runs = index.consecutive_successful_runs.saturating_add(1);
        }
        RunStatus::Failed => {
            index.failed += 1;
            index.consecutive_successful_runs = 0;
        }
        RunStatus::Interrupted => {
            index.interrupted += 1;
            index.consecutive_successful_runs = 0;
        }
        RunStatus::Running | RunStatus::Finalizing => {}
    }

    let executed_cases = state
        .cases
        .iter()
        .filter(|case| case.status != CaseStatus::Pending)
        .count() as u64;
    let successful_cases = state
        .cases
        .iter()
        .filter(|case| case.status == CaseStatus::Passed)
        .count() as u64;
    index.replayed_cases = index.replayed_cases.saturating_add(executed_cases);
    index.passed_cases = index.passed_cases.saturating_add(successful_cases);
    index.failed_cases = index.failed_cases.saturating_add(
        state
            .cases
            .iter()
            .filter(|case| case.status == CaseStatus::Failed)
            .count() as u64,
    );
    index.incomplete_cases = index.incomplete_cases.saturating_add(
        state
            .cases
            .iter()
            .filter(|case| {
                matches!(
                    case.status,
                    CaseStatus::Incomplete | CaseStatus::Pending | CaseStatus::Running
                )
            })
            .count() as u64,
    );
    index.consecutive_successful_cases = if state.status == RunStatus::Successful {
        index
            .consecutive_successful_cases
            .saturating_add(successful_cases)
    } else {
        0
    };
}

fn update_api_progress(
    progress: &mut ApiProgress,
    state: &ActiveRunState,
    api: &ApiExecution,
    global_evidence_clean: bool,
) {
    progress.cases = api.total;
    progress.status.clear();
    progress.executions = progress.executions.saturating_add(1);
    let api_executed_cases = state
        .cases
        .iter()
        .filter(|case| case.group_id == api.group_id && case.status != CaseStatus::Pending)
        .count() as u64;
    progress.executed_cases = progress.executed_cases.saturating_add(api_executed_cases);
    progress.successful_cases = progress
        .successful_cases
        .saturating_add(u64::from(api.passed));

    let successful = global_evidence_clean && api.successful;
    if successful {
        progress.successful = progress.successful.saturating_add(1);
        progress.consecutive_successful_runs =
            progress.consecutive_successful_runs.saturating_add(1);
        progress.consecutive_successful_cases = progress
            .consecutive_successful_cases
            .saturating_add(u64::from(api.passed));
    } else {
        progress.consecutive_successful_runs = 0;
        progress.consecutive_successful_cases = 0;
    }
}

pub(super) fn refresh_verification(index: &mut RunIndex, verification: &ApiVerificationConfig) {
    for (api_key, progress) in &mut index.apis {
        let thresholds = verification.thresholds_for(api_key);
        progress.verified = progress.consecutive_successful_runs
            >= thresholds.consecutive_successful_runs
            && progress.consecutive_successful_cases >= thresholds.successful_cases;
    }
}

pub(super) fn build_progress(index: &RunIndex, state: &ActiveRunState) -> ProgressReport {
    let verified = index.apis.values().filter(|api| api.verified).count() as u32;
    let complete =
        index.inventory_complete && !index.apis.is_empty() && verified == index.apis.len() as u32;
    let latest_cases = LatestCounts {
        executed: state
            .cases
            .iter()
            .filter(|case| case.status != CaseStatus::Pending)
            .count() as u32,
        successful: state
            .cases
            .iter()
            .filter(|case| case.status == CaseStatus::Passed)
            .count() as u32,
    };

    ProgressReport {
        version: STATE_VERSION,
        updated_at: state
            .finished_at
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
        status: if complete {
            "complete".to_string()
        } else {
            "in_progress".to_string()
        },
        run: ProgressRun {
            key: state.run_key.clone(),
        },
        progress: ProgressSummary {
            runs: SuccessCounts {
                executed: index.executions,
                successful: index.successful,
                consecutive_successful: index.consecutive_successful_runs,
            },
            cases: SuccessCounts {
                executed: index.replayed_cases,
                successful: index.passed_cases,
                consecutive_successful: index.consecutive_successful_cases,
            },
            apis: ApiCounts {
                total: index.apis.len() as u32,
                verified,
            },
        },
        latest_run: LatestRun {
            number: index.executions,
            successful: state.status == RunStatus::Successful,
            cases: latest_cases,
            apis: LatestCounts {
                executed: state.apis.len() as u32,
                successful: state.apis.iter().filter(|api| api.successful).count() as u32,
            },
        },
        apis: index
            .apis
            .iter()
            .map(|(api_key, api)| {
                (
                    api_key.clone(),
                    ProgressApi {
                        verified: api.verified,
                        runs: SuccessCounts {
                            executed: api.executions,
                            successful: api.successful,
                            consecutive_successful: api.consecutive_successful_runs,
                        },
                        cases: SuccessCounts {
                            executed: api.executed_cases,
                            successful: api.successful_cases,
                            consecutive_successful: api.consecutive_successful_cases,
                        },
                    },
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
    use crate::e2e_run::model::{
        ApiExecution, ApiProgress, ApiVerificationThresholds, CaseExecution,
    };

    fn verification(runs: u64, cases: u64) -> ApiVerificationConfig {
        ApiVerificationConfig {
            consecutive_successful_runs: runs,
            successful_cases: cases,
            overrides: BTreeMap::new(),
        }
    }

    fn state(api_passed: u32, api_failed: u32, status: RunStatus) -> ActiveRunState {
        let cases = (0..api_passed)
            .map(|index| CaseExecution {
                case_id: format!("passed-{index}"),
                case_dir: PathBuf::from("/cases"),
                group_id: "GET /api/orders/*".to_string(),
                status: CaseStatus::Passed,
                assertion_passed: Some(true),
                replay_clean: Some(true),
                response_assertion: None,
            })
            .chain((0..api_failed).map(|index| CaseExecution {
                case_id: format!("failed-{index}"),
                case_dir: PathBuf::from("/cases"),
                group_id: "GET /api/orders/*".to_string(),
                status: CaseStatus::Failed,
                assertion_passed: Some(false),
                replay_clean: Some(true),
                response_assertion: None,
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

    fn inventory() -> CaseGroupInventory {
        CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![
                CanonicalCaseGroup {
                    group_id: "GET /api/orders/*".to_string(),
                    method: "GET".to_string(),
                    source_route: "/api/orders/:id".to_string(),
                    pattern: Some("/api/orders/*".to_string()),
                    case_inventory_id: "inventory".to_string(),
                    cases: (0..3)
                        .map(|index| CanonicalCase {
                            case_id: format!("passed-{index}"),
                            case_dir: PathBuf::from("/cases"),
                        })
                        .collect(),
                },
                CanonicalCaseGroup {
                    group_id: "POST /api/payments".to_string(),
                    method: "POST".to_string(),
                    source_route: "/api/payments".to_string(),
                    pattern: None,
                    case_inventory_id: "inventory".to_string(),
                    cases: vec![CanonicalCase {
                        case_id: "payment-passed".to_string(),
                        case_dir: PathBuf::from("/cases"),
                    }],
                },
            ],
        }
    }

    #[test]
    fn verification_requires_both_round_and_case_thresholds() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let first = state(2, 0, RunStatus::Successful);

        update_index(&mut index, &first, &verification(2, 5));
        assert!(!index.apis["GET /api/orders/*"].verified);

        let mut second = first.clone();
        second.sequence = 2;
        update_index(&mut index, &second, &verification(2, 5));
        assert!(!index.apis["GET /api/orders/*"].verified);

        let mut third = state(3, 0, RunStatus::Successful);
        third.sequence = 3;
        update_index(&mut index, &third, &verification(2, 5));
        assert!(index.apis["GET /api/orders/*"].verified);
        assert_eq!(index.consecutive_successful_runs, 3);
        assert_eq!(index.consecutive_successful_cases, 7);
    }

    #[test]
    fn failed_round_resets_round_and_covered_case_streaks() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let first = state(3, 0, RunStatus::Successful);
        update_index(&mut index, &first, &verification(2, 6));

        let mut second = first.clone();
        second.sequence = 2;
        update_index(&mut index, &second, &verification(2, 6));
        assert!(index.apis["GET /api/orders/*"].verified);

        let mut failed = state(2, 1, RunStatus::Failed);
        failed.sequence = 3;
        update_index(&mut index, &failed, &verification(2, 6));
        let api = &index.apis["GET /api/orders/*"];
        assert!(!api.verified);
        assert_eq!(api.consecutive_successful_runs, 0);
        assert_eq!(api.consecutive_successful_cases, 0);
        assert_eq!(index.consecutive_successful_runs, 0);
        assert_eq!(index.consecutive_successful_cases, 0);
    }

    #[test]
    fn successful_api_accumulates_when_another_api_fails() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let mut round = state(3, 0, RunStatus::Failed);
        round.cases.push(CaseExecution {
            case_id: "payment-failed".to_string(),
            case_dir: PathBuf::from("/cases"),
            group_id: "POST /api/payments".to_string(),
            status: CaseStatus::Failed,
            assertion_passed: Some(false),
            replay_clean: Some(true),
            response_assertion: None,
        });
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

        update_index(&mut index, &round, &verification(1, 3));

        assert!(index.apis["GET /api/orders/*"].verified);
        assert!(!index.apis["POST /api/payments"].verified);
    }

    #[test]
    fn publishing_same_sequence_is_idempotent() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let completed = state(3, 0, RunStatus::Successful);
        update_index(&mut index, &completed, &verification(1, 3));
        update_index(&mut index, &completed, &verification(1, 3));

        assert_eq!(index.executions, 1);
        assert_eq!(index.replayed_cases, 3);
        assert_eq!(index.successful, 1);
    }

    #[test]
    fn focused_api_rounds_update_progress_and_can_complete_all_groups() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let orders = state(3, 0, RunStatus::Successful);

        update_focused_index(&mut index, &orders, &inventory(), true, &verification(1, 1));

        assert_eq!(index.executions, 1);
        assert!(index.apis["GET /api/orders/*"].verified);
        assert!(!index.apis["POST /api/payments"].verified);
        assert_eq!(build_progress(&index, &orders).status, "in_progress");

        let mut payment = state(1, 0, RunStatus::Successful);
        payment.cases[0].case_id = "payment-passed".to_string();
        payment.cases[0].group_id = "POST /api/payments".to_string();
        payment.apis[0] = ApiExecution {
            api_key: "POST /api/payments".to_string(),
            group_id: "POST /api/payments".to_string(),
            method: "POST".to_string(),
            api_pattern: "/api/payments".to_string(),
            case_ids: vec!["payment-passed".to_string()],
            total: 1,
            passed: 1,
            failed: 0,
            incomplete: 0,
            successful: true,
            ensure_status: None,
            report_dir: PathBuf::from("apis/api-0001"),
        };

        update_focused_index(
            &mut index,
            &payment,
            &inventory(),
            true,
            &verification(1, 1),
        );

        assert_eq!(index.executions, 2);
        assert!(index.apis.values().all(|api| api.verified));
        assert_eq!(build_progress(&index, &payment).status, "complete");
    }

    #[test]
    fn focused_apis_use_individual_verification_overrides() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let mut policy = verification(1, 1);
        policy.overrides.insert(
            "POST /api/payments".to_string(),
            ApiVerificationThresholds {
                consecutive_successful_runs: 2,
                successful_cases: 2,
            },
        );
        let orders = state(3, 0, RunStatus::Successful);
        update_focused_index(&mut index, &orders, &inventory(), true, &policy);

        let mut payment = state(1, 0, RunStatus::Successful);
        payment.cases[0].case_id = "payment-passed".to_string();
        payment.cases[0].group_id = "POST /api/payments".to_string();
        payment.apis[0] = ApiExecution {
            api_key: "POST /api/payments".to_string(),
            group_id: "POST /api/payments".to_string(),
            method: "POST".to_string(),
            api_pattern: "/api/payments".to_string(),
            case_ids: vec!["payment-passed".to_string()],
            total: 1,
            passed: 1,
            failed: 0,
            incomplete: 0,
            successful: true,
            ensure_status: None,
            report_dir: PathBuf::from("apis/api-0001"),
        };
        update_focused_index(&mut index, &payment, &inventory(), true, &policy);

        assert!(index.apis["GET /api/orders/*"].verified);
        assert!(!index.apis["POST /api/payments"].verified);

        payment.sequence = 2;
        update_focused_index(&mut index, &payment, &inventory(), true, &policy);

        assert!(index.apis["POST /api/payments"].verified);
    }

    #[test]
    fn changed_baseline_starts_new_streaks() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let first = state(3, 0, RunStatus::Successful);
        update_index(&mut index, &first, &verification(2, 6));
        let mut changed = first.clone();
        changed.sequence = 2;
        changed.case_inventory_id = "changed-inventory".to_string();
        update_index(&mut index, &changed, &verification(2, 6));

        assert_eq!(index.consecutive_successful_runs, 1);
        assert_eq!(index.consecutive_successful_cases, 3);
        assert!(!index.apis["GET /api/orders/*"].verified);
    }

    #[test]
    fn legacy_progress_is_migrated_as_a_conservative_single_round_streak() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        index.executions = 1;
        index.successful = 1;
        index.latest_status = Some(RunStatus::Successful);
        index.apis.insert(
            "GET /api/orders/*".to_string(),
            ApiProgress {
                cases: 3,
                status: "verified".to_string(),
                ..ApiProgress::default()
            },
        );

        index.normalize_legacy_progress();
        refresh_verification(&mut index, &verification(2, 6));

        let api = &index.apis["GET /api/orders/*"];
        assert_eq!(index.consecutive_successful_runs, 1);
        assert_eq!(index.consecutive_successful_cases, 3);
        assert_eq!(api.executions, 1);
        assert_eq!(api.successful, 1);
        assert_eq!(api.consecutive_successful_runs, 1);
        assert_eq!(api.consecutive_successful_cases, 3);
        assert!(!api.verified);
    }

    #[test]
    fn human_progress_uses_only_simplified_success_counts() {
        let mut index = RunIndex::empty("run".to_string(), PathBuf::from("/cases"));
        let completed = state(3, 0, RunStatus::Successful);
        update_index(&mut index, &completed, &verification(1, 3));
        let yaml = serde_yaml::to_string(&build_progress(&index, &completed)).unwrap();

        assert!(yaml.contains("consecutive_successful: 3"));
        assert!(yaml.contains("verified: true"));
        for omitted in [
            "failed:",
            "incomplete:",
            "interrupted:",
            "replayed:",
            "passed:",
            "needs_attention",
            "highlights:",
        ] {
            assert!(!yaml.contains(omitted), "{omitted} leaked into progress");
        }
    }
}
