use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::model::{ActiveRunState, ApiExecution, ApiProgress, RunIndex};
use super::store;
use crate::case_group::CaseGroupInventory;

const PROGRESS_VERSION: u32 = 3;

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
    #[serde(default, alias = "successful")]
    passed: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct ApiCounts {
    total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestRun {
    number: u64,
    #[serde(alias = "successful")]
    passed: bool,
    cases: LatestCounts,
    apis: LatestCounts,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct LatestCounts {
    executed: u32,
    #[serde(alias = "successful")]
    passed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressApi {
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
        matches!(report.version, 1 | 2 | PROGRESS_VERSION),
        "unsupported E2E progress version {}",
        report.version
    );
    let mut index = RunIndex::empty(run_key, case_source);
    index.executions = report.progress.runs.executed;
    index.passed_runs = report.progress.runs.passed;
    index.replayed_cases = report.progress.cases.executed;
    index.passed_cases = report.progress.cases.passed;
    index.apis = report
        .apis
        .into_iter()
        .map(|(api_key, api)| {
            (
                api_key,
                ApiProgress {
                    executions: api.runs.executed,
                    passed_runs: api.runs.passed,
                    executed_cases: api.cases.executed,
                    passed_cases: api.cases.passed,
                    ..ApiProgress::default()
                },
            )
        })
        .collect();
    Ok(index)
}

pub(super) fn update_index(index: &mut RunIndex, state: &ActiveRunState) {
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
}

pub(super) fn update_focused_index(
    index: &mut RunIndex,
    state: &ActiveRunState,
    inventory: &CaseGroupInventory,
    inventory_complete: bool,
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
}

fn reconcile_baseline(index: &mut RunIndex, state: &ActiveRunState) {
    let baseline_changed = (!index.source_revision.is_empty()
        && index.source_revision != state.source_revision)
        || (!index.case_inventory_id.is_empty()
            && index.case_inventory_id != state.case_inventory_id);
    if baseline_changed {
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
        contribution.counted = true;
        progress.executions = progress.executions.saturating_add(1);
    }

    progress.cases = api.total;
    progress.status.clear();
    progress.executed_cases = progress
        .executed_cases
        .saturating_sub(contribution.executed_cases)
        .saturating_add(u64::from(api.total));
    progress.passed_cases = progress
        .passed_cases
        .saturating_sub(contribution.passed_cases)
        .saturating_add(u64::from(api.passed));
    let passed = global_evidence_clean && api.complete_pass;
    progress.passed_runs = progress
        .passed_runs
        .saturating_sub(u64::from(contribution.passed))
        .saturating_add(u64::from(passed));
    contribution.passed = passed;
    contribution.executed_cases = u64::from(api.total);
    contribution.passed_cases = u64::from(api.passed);
}

fn update_current_run_totals(index: &mut RunIndex, state: &ActiveRunState) {
    let executed_cases = index
        .current_run
        .apis
        .values()
        .filter(|api| api.counted)
        .map(|api| api.executed_cases)
        .sum::<u64>();
    let passed_cases = index
        .current_run
        .apis
        .values()
        .filter(|api| api.counted)
        .map(|api| api.passed_cases)
        .sum::<u64>();
    index.replayed_cases = index
        .replayed_cases
        .saturating_sub(index.current_run.executed_cases)
        .saturating_add(executed_cases);
    index.passed_cases = index
        .passed_cases
        .saturating_sub(index.current_run.passed_cases)
        .saturating_add(passed_cases);

    let passed = index.inventory_complete
        && !index.current_run.api_keys.is_empty()
        && index.current_run.api_keys.iter().all(|api_key| {
            index
                .current_run
                .apis
                .get(api_key)
                .is_some_and(|api| api.counted && api.passed)
        });
    index.passed_runs = index
        .passed_runs
        .saturating_sub(u64::from(index.current_run.passed))
        .saturating_add(u64::from(passed));
    index.current_run.passed = passed;
    index.current_run.executed_cases = executed_cases;
    index.current_run.passed_cases = passed_cases;
    index.latest_status = Some(state.status);
}

pub(super) fn build_progress(index: &RunIndex, state: &ActiveRunState) -> ProgressReport {
    let passed_apis = index
        .current_run
        .api_keys
        .iter()
        .filter(|api_key| {
            index
                .current_run
                .apis
                .get(*api_key)
                .is_some_and(|api| api.counted && api.passed)
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
        status: if index.current_run.passed {
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
                passed: index.passed_runs,
            },
            cases: SuccessCounts {
                executed: index.replayed_cases,
                passed: index.passed_cases,
            },
            apis: ApiCounts {
                total: index.apis.len() as u32,
            },
        },
        latest_run: LatestRun {
            number: index.executions,
            passed: index.current_run.passed,
            cases: LatestCounts {
                executed: u32::try_from(index.current_run.executed_cases).unwrap_or(u32::MAX),
                passed: u32::try_from(index.current_run.passed_cases).unwrap_or(u32::MAX),
            },
            apis: LatestCounts {
                executed: executed_apis,
                passed: passed_apis,
            },
        },
        apis: index
            .apis
            .iter()
            .map(|(api_key, api)| {
                (
                    api_key.clone(),
                    ProgressApi {
                        runs: SuccessCounts {
                            executed: api.executions,
                            passed: api.passed_runs,
                        },
                        cases: SuccessCounts {
                            executed: api.executed_cases,
                            passed: api.passed_cases,
                        },
                    },
                )
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
