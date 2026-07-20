use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::model::{ActiveRunState, ApiExecution, ApiProgress, ApiVerificationConfig, RunIndex};
use super::store;
use crate::case_group::CaseGroupInventory;

const PROGRESS_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ProgressReport {
    version: u32,
    updated_at: String,
    status: String,
    run: ProgressRun,
    progress: ProgressSummary,
    latest_run: LatestRun,
    apis: BTreeMap<String, ProgressApi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressRun {
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressSummary {
    runs: SuccessCounts,
    cases: SuccessCounts,
    apis: ApiCounts,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SuccessCounts {
    executed: u64,
    successful: u64,
    consecutive_successful: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct ApiCounts {
    total: u32,
    verified: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestRun {
    number: u64,
    successful: bool,
    cases: LatestCounts,
    apis: LatestCounts,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct LatestCounts {
    executed: u32,
    successful: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressApi {
    verified: bool,
    runs: SuccessCounts,
    cases: SuccessCounts,
}

pub(super) fn load_progress_baseline(
    progress_path: &Path,
    run_key: String,
    case_source: PathBuf,
) -> Result<RunIndex> {
    if !progress_path.is_file() {
        return Ok(RunIndex::empty(run_key, case_source));
    }
    let report: ProgressReport = store::read_yaml(progress_path)?;
    ensure!(
        matches!(report.version, 1 | PROGRESS_VERSION),
        "unsupported E2E progress version {}",
        report.version
    );
    let report = if report.version == 1 {
        normalize_legacy_report(report)
    } else {
        report
    };
    let mut index = RunIndex::empty(run_key, case_source);
    index.executions = report.progress.runs.executed;
    index.successful = report.progress.runs.successful;
    index.consecutive_successful_runs = report.progress.runs.consecutive_successful;
    index.replayed_cases = report.progress.cases.executed;
    index.passed_cases = report.progress.cases.successful;
    index.consecutive_successful_cases = report.progress.cases.consecutive_successful;
    index.current_run.baseline_consecutive_successful_runs =
        report.progress.runs.consecutive_successful;
    index.current_run.baseline_consecutive_successful_cases =
        report.progress.cases.consecutive_successful;
    index.apis = report
        .apis
        .into_iter()
        .map(|(api_key, api)| {
            (
                api_key,
                ApiProgress {
                    executions: api.runs.executed,
                    successful: api.runs.successful,
                    consecutive_successful_runs: api.runs.consecutive_successful,
                    executed_cases: api.cases.executed,
                    successful_cases: api.cases.successful,
                    consecutive_successful_cases: api.cases.consecutive_successful,
                    verified: api.verified,
                    ..ApiProgress::default()
                },
            )
        })
        .collect();
    Ok(index)
}

fn normalize_legacy_report(mut report: ProgressReport) -> ProgressReport {
    let run_counted = report.progress.runs.executed > 0;
    let run_successful = run_counted && report.latest_run.successful;
    report.version = PROGRESS_VERSION;
    report.progress.runs = SuccessCounts {
        executed: u64::from(run_counted),
        successful: u64::from(run_successful),
        consecutive_successful: u64::from(run_successful),
    };
    report.progress.cases = SuccessCounts {
        executed: u64::from(report.latest_run.cases.executed),
        successful: u64::from(report.latest_run.cases.successful),
        consecutive_successful: if run_successful {
            u64::from(report.latest_run.cases.successful)
        } else {
            0
        },
    };
    report.progress.apis.verified = 0;
    report.latest_run.number = u64::from(run_counted);
    for api in report.apis.values_mut() {
        let old_runs = api.runs;
        let old_cases = api.cases;
        let counted = old_runs.executed > 0;
        let successful = counted && old_runs.consecutive_successful > 0;
        let current_cases = if old_runs.consecutive_successful > 0 {
            old_cases
                .consecutive_successful
                .checked_div(old_runs.consecutive_successful)
                .unwrap_or(0)
        } else {
            old_cases
                .executed
                .checked_div(old_runs.executed)
                .unwrap_or(0)
        };
        api.verified = false;
        api.runs = SuccessCounts {
            executed: u64::from(counted),
            successful: u64::from(successful),
            consecutive_successful: u64::from(successful),
        };
        api.cases = SuccessCounts {
            executed: current_cases,
            successful: if successful { current_cases } else { 0 },
            consecutive_successful: if successful { current_cases } else { 0 },
        };
    }
    report
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
    count_current_run(index);
    index.latest_sequence = Some(state.sequence);

    let global_evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    index.current_run.api_keys = state
        .apis
        .iter()
        .map(|api| api.api_key.clone())
        .collect::<BTreeSet<_>>();
    for api in &state.apis {
        update_api_progress(index, api, global_evidence_clean);
    }
    update_current_run_totals(index, state);
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
    count_current_run(index);
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
    index.current_run.api_keys = current_apis.keys().cloned().collect();
    for (api_key, cases) in &current_apis {
        index.apis.entry(api_key.clone()).or_default().cases = *cases;
    }
    let global_evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    update_api_progress(index, api, global_evidence_clean);
    update_current_run_totals(index, state);
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
        index.current_run.baseline_consecutive_successful_runs = 0;
        index.current_run.baseline_consecutive_successful_cases = 0;
        for api in index.apis.values_mut() {
            api.consecutive_successful_runs = 0;
            api.consecutive_successful_cases = 0;
            api.verified = false;
        }
        for contribution in index.current_run.apis.values_mut() {
            contribution.baseline_consecutive_successful_runs = 0;
            contribution.baseline_consecutive_successful_cases = 0;
        }
        index.latest_focused_sequences.clear();
    }
    index.source_revision = state.source_revision.clone();
    index.case_inventory_id = state.case_inventory_id.clone();
}

fn count_current_run(index: &mut RunIndex) {
    if index.current_run.counted {
        return;
    }
    index.current_run.counted = true;
    index.current_run.baseline_consecutive_successful_runs = index.consecutive_successful_runs;
    index.current_run.baseline_consecutive_successful_cases = index.consecutive_successful_cases;
    index.executions = index.executions.saturating_add(1);
}

fn update_api_progress(index: &mut RunIndex, api: &ApiExecution, global_evidence_clean: bool) {
    let progress = index.apis.entry(api.api_key.clone()).or_default();
    let contribution = index
        .current_run
        .apis
        .entry(api.api_key.clone())
        .or_default();
    if !contribution.counted {
        contribution.baseline_consecutive_successful_runs = progress.consecutive_successful_runs;
        contribution.baseline_consecutive_successful_cases = progress.consecutive_successful_cases;
        contribution.counted = true;
        progress.executions = progress.executions.saturating_add(1);
    }

    progress.cases = api.total;
    progress.status.clear();
    progress.executed_cases = progress
        .executed_cases
        .saturating_sub(contribution.executed_cases)
        .saturating_add(u64::from(api.total));
    progress.successful_cases = progress
        .successful_cases
        .saturating_sub(contribution.successful_cases)
        .saturating_add(u64::from(api.passed));
    let successful = global_evidence_clean && api.successful;
    progress.successful = progress
        .successful
        .saturating_sub(u64::from(contribution.successful))
        .saturating_add(u64::from(successful));
    if successful {
        progress.consecutive_successful_runs = contribution
            .baseline_consecutive_successful_runs
            .saturating_add(1);
        progress.consecutive_successful_cases = contribution
            .baseline_consecutive_successful_cases
            .saturating_add(u64::from(api.passed));
    } else {
        progress.consecutive_successful_runs = 0;
        progress.consecutive_successful_cases = 0;
    }
    contribution.successful = successful;
    contribution.executed_cases = u64::from(api.total);
    contribution.successful_cases = u64::from(api.passed);
}

fn update_current_run_totals(index: &mut RunIndex, state: &ActiveRunState) {
    let executed_cases = index
        .current_run
        .apis
        .values()
        .filter(|api| api.counted)
        .map(|api| api.executed_cases)
        .sum::<u64>();
    let successful_cases = index
        .current_run
        .apis
        .values()
        .filter(|api| api.counted)
        .map(|api| api.successful_cases)
        .sum::<u64>();
    index.replayed_cases = index
        .replayed_cases
        .saturating_sub(index.current_run.executed_cases)
        .saturating_add(executed_cases);
    index.passed_cases = index
        .passed_cases
        .saturating_sub(index.current_run.successful_cases)
        .saturating_add(successful_cases);

    let successful = index.inventory_complete
        && !index.current_run.api_keys.is_empty()
        && index.current_run.api_keys.iter().all(|api_key| {
            index
                .current_run
                .apis
                .get(api_key)
                .is_some_and(|api| api.counted && api.successful)
        });
    index.successful = index
        .successful
        .saturating_sub(u64::from(index.current_run.successful))
        .saturating_add(u64::from(successful));
    if successful {
        index.consecutive_successful_runs = index
            .current_run
            .baseline_consecutive_successful_runs
            .saturating_add(1);
        index.consecutive_successful_cases = index
            .current_run
            .baseline_consecutive_successful_cases
            .saturating_add(successful_cases);
    } else {
        index.consecutive_successful_runs = 0;
        index.consecutive_successful_cases = 0;
    }
    index.current_run.successful = successful;
    index.current_run.executed_cases = executed_cases;
    index.current_run.successful_cases = successful_cases;
    index.latest_status = Some(state.status);
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
    let successful_apis = index
        .current_run
        .api_keys
        .iter()
        .filter(|api_key| {
            index
                .current_run
                .apis
                .get(*api_key)
                .is_some_and(|api| api.counted && api.successful)
        })
        .count() as u32;
    let executed_apis = index
        .current_run
        .api_keys
        .iter()
        .filter(|api_key| {
            index
                .current_run
                .apis
                .get(*api_key)
                .is_some_and(|api| api.counted)
        })
        .count() as u32;

    ProgressReport {
        version: PROGRESS_VERSION,
        updated_at: state
            .finished_at
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
        status: if index.current_run.successful {
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
            successful: index.current_run.successful,
            cases: LatestCounts {
                executed: u32::try_from(index.current_run.executed_cases).unwrap_or(u32::MAX),
                successful: u32::try_from(index.current_run.successful_cases).unwrap_or(u32::MAX),
            },
            apis: LatestCounts {
                executed: executed_apis,
                successful: successful_apis,
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
mod tests;
