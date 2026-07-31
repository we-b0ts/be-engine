use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::model::{ActiveRunState, ApiExecution, RunIndex};
use super::store;
use crate::case_group::CaseGroupInventory;
use crate::verification_progress::{
    ApiCounts, ApiObservation, ApiTotals, LatestCounts, LatestRun, ProgressApi,
    ProgressObservation, ProgressReport, ProgressTotals, SuccessCounts, SuccessStreak,
    VerificationStage, fingerprint, load, write,
};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayRunKind {
    Full,
    Focused,
}

#[derive(Debug, Deserialize)]
struct LegacyProgressReport {
    version: u32,
    updated_at: String,
    run: LegacyProgressRun,
    progress: LegacyProgressSummary,
    latest_run: LegacyLatestRun,
    apis: BTreeMap<String, LegacyProgressApi>,
}

#[derive(Debug, Deserialize)]
struct LegacyProgressRun {
    key: String,
}

#[derive(Debug, Deserialize)]
struct LegacyProgressSummary {
    runs: LegacySuccessCounts,
    cases: LegacySuccessCounts,
    apis: ApiCounts,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct LegacySuccessCounts {
    executed: u64,
    #[serde(default, alias = "successful")]
    passed: u64,
}

#[derive(Debug, Deserialize)]
struct LegacyLatestRun {
    number: u64,
    #[serde(alias = "successful")]
    passed: bool,
    cases: LatestCounts,
    apis: LatestCounts,
}

#[derive(Debug, Deserialize)]
struct LegacyProgressApi {
    runs: LegacySuccessCounts,
    cases: LegacySuccessCounts,
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

pub(super) fn write_replay_progress(
    progress_path: &Path,
    legacy_progress_path: &Path,
    state: &ActiveRunState,
    kind: ReplayRunKind,
) -> Result<()> {
    let mut migrated = false;
    let mut report = match load(progress_path, VerificationStage::Replay)? {
        Some(report) => report,
        None if legacy_progress_path.is_file() => {
            migrated = true;
            load_legacy_progress(legacy_progress_path)?
        }
        None => ProgressReport::new(VerificationStage::Replay),
    };
    let applied = report.apply(observation(state, kind)?)?;
    if applied || migrated {
        write(progress_path, &report)?;
    }
    if progress_path != legacy_progress_path && legacy_progress_path.exists() {
        remove_legacy_progress(legacy_progress_path)?;
    }
    Ok(())
}

fn observation(state: &ActiveRunState, kind: ReplayRunKind) -> Result<ProgressObservation> {
    ensure!(
        state.status.is_terminal(),
        "replay progress requires a terminal run"
    );
    ensure!(
        !state.apis.is_empty(),
        "replay progress requires at least one summarized API"
    );
    if matches!(kind, ReplayRunKind::Focused) {
        ensure!(
            state.apis.len() == 1,
            "focused replay progress requires exactly one API"
        );
    }
    let evidence_clean =
        state.replay_finalized && state.aggregate_complete && state.aggregate_clean;
    let apis = state
        .apis
        .iter()
        .map(|api| {
            (
                api.api_key.clone(),
                ApiObservation {
                    cases: LatestCounts {
                        executed: u64::from(api.total),
                        passed: u64::from(api.passed),
                    },
                    passed: evidence_clean && api.complete_pass,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let scope = state
        .apis
        .iter()
        .map(|api| ReplayApiEvidence {
            api: &api.api_key,
            total: api.total,
            passed: api.passed,
            failed: api.failed,
            incomplete: api.incomplete,
            complete_pass: api.complete_pass,
        })
        .collect::<Vec<_>>();
    let evidence = ReplayEvidence {
        run_key: &state.run_key,
        sequence: state.sequence,
        kind,
        source_revision: &state.source_revision,
        case_inventory_id: &state.case_inventory_id,
        replay_finalized: state.replay_finalized,
        aggregate_complete: state.aggregate_complete,
        aggregate_clean: state.aggregate_clean,
        apis: scope,
    };
    let evidence_bytes = serde_json::to_vec(&evidence)?;
    let scope_key = state
        .apis
        .iter()
        .map(|api| api.api_key.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Ok(ProgressObservation {
        key: format!(
            "{}|{}|{}|{}",
            state.run_key,
            match kind {
                ReplayRunKind::Full => "full",
                ReplayRunKind::Focused => "focused",
            },
            scope_key,
            state.sequence
        ),
        evidence_fingerprint: fingerprint(&evidence_bytes),
        finished_at: state
            .finished_at
            .context("terminal replay run is missing finished_at")?
            .to_rfc3339(),
        apis,
    })
}

#[derive(Serialize)]
struct ReplayEvidence<'a> {
    run_key: &'a str,
    sequence: u64,
    kind: ReplayRunKind,
    source_revision: &'a str,
    case_inventory_id: &'a str,
    replay_finalized: bool,
    aggregate_complete: bool,
    aggregate_clean: bool,
    apis: Vec<ReplayApiEvidence<'a>>,
}

#[derive(Serialize)]
struct ReplayApiEvidence<'a> {
    api: &'a str,
    total: u32,
    passed: u32,
    failed: u32,
    incomplete: u32,
    complete_pass: bool,
}

fn load_legacy_progress(path: &Path) -> Result<ProgressReport> {
    let legacy: LegacyProgressReport = store::read_yaml(path)?;
    ensure!(
        matches!(legacy.version, 1..=3),
        "unsupported legacy E2E progress version {}",
        legacy.version
    );
    let success_streak = if legacy.latest_run.passed {
        SuccessStreak {
            runs: 1,
            cases: legacy.latest_run.cases.executed,
        }
    } else {
        SuccessStreak::default()
    };
    Ok(ProgressReport {
        version: crate::verification_progress::PROGRESS_VERSION,
        stage: VerificationStage::Replay,
        updated_at: legacy.updated_at,
        totals: ProgressTotals {
            runs: SuccessCounts {
                executed: legacy.progress.runs.executed,
                passed: legacy.progress.runs.passed,
            },
            cases: SuccessCounts {
                executed: legacy.progress.cases.executed,
                passed: legacy.progress.cases.passed,
            },
            apis: legacy.progress.apis,
        },
        success_streak,
        latest_run: Some(LatestRun {
            key: legacy.run.key.clone(),
            evidence_fingerprint: format!("legacy-v{}:{}", legacy.version, legacy.run.key),
            number: legacy.latest_run.number,
            passed: legacy.latest_run.passed,
            cases: legacy.latest_run.cases,
            apis: legacy.latest_run.apis,
            scope: Vec::new(),
        }),
        apis: legacy
            .apis
            .into_iter()
            .map(|(api, progress)| {
                (
                    api,
                    ProgressApi {
                        totals: ApiTotals {
                            runs: SuccessCounts {
                                executed: progress.runs.executed,
                                passed: progress.runs.passed,
                            },
                            cases: SuccessCounts {
                                executed: progress.cases.executed,
                                passed: progress.cases.passed,
                            },
                        },
                        success_streak: SuccessStreak::default(),
                    },
                )
            })
            .collect(),
    })
}

fn remove_legacy_progress(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect legacy progress {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "legacy progress must be a regular file and not a symlink: {}",
        path.display()
    );
    fs::remove_file(path)
        .with_context(|| format!("failed to remove migrated progress {}", path.display()))
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

#[cfg(test)]
mod tests;
