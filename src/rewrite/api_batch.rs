//! Route acceptance prepares and transitions method slices as one Replay batch.
use anyhow::{Result, ensure};
use std::path::Path;

use super::{
    api_selector, inventory,
    model::{RewriteApiStatus, RewritePhase, RewriteSliceState, RewriteState},
    preparation, transition,
};

pub(super) struct PreparedRoute {
    pub apis: Vec<String>,
    pub slices: std::collections::BTreeMap<String, RewriteSliceState>,
}

pub(super) fn prepare(target_root: &Path, state: &RewriteState) -> Result<PreparedRoute> {
    let selector = api_selector::RewriteApiSelector::Route(api_selector::route(&state.api).into());
    let mut apis = api_selector::members(state, &selector)
        .into_iter()
        .filter(|api| {
            !super::regression_scope::is_skipped(state, api)
                && state
                    .api_inventory
                    .iter()
                    .find(|item| item.api == *api)
                    .is_some_and(|item| {
                        !matches!(
                            item.status,
                            RewriteApiStatus::SystemRepairRequired
                                | RewriteApiStatus::AwaitingRecordingRefresh
                        )
                    })
        })
        .collect::<Vec<_>>();
    ensure!(!apis.is_empty(), "route has no replayable method cases");
    // Keep the active method as the runtime owner so existing focused recovery
    // resolves the same directory after an interrupted route session.
    apis.sort_by_key(|api| api != &state.api);
    let mut slices = std::collections::BTreeMap::new();
    let mut selected_apis = Vec::new();
    for api in &apis {
        let mut scoped = inventory::scoped(state, Some(&api.parse()?))?;
        // A route batch cannot consume another method's unaccepted external repair.
        ensure!(
            scoped.phase != RewritePhase::SystemRepairRequired,
            "API {api} must finish its system repair before route acceptance"
        );
        if scoped.phase == RewritePhase::ImplementationRequired {
            let scope = super::RewriteWorkScope::Api { api: api.clone() };
            if super::worker::scheduler::acceptance_gate(target_root, &scoped, &scope).is_some() {
                // Discover untouched siblings without consuming an unintegrated
                // failed method. Its existing issue/worker remains outstanding.
                continue;
            }
        }
        preparation::prepare_recording(target_root, &mut scoped)?;
        selected_apis.push(api.clone());
        slices.insert(api.clone(), scoped.active_slice);
    }
    ensure!(
        !selected_apis.is_empty(),
        "route methods require their reviewed handoff or precise rule/system-repair acceptance before Replay"
    );
    Ok(PreparedRoute {
        apis: selected_apis,
        slices,
    })
}

pub(super) fn apply_results(
    target_root: &Path,
    state: &mut RewriteState,
    results: &[crate::E2eApiRunResult],
    prepared: Option<&PreparedRoute>,
) -> Result<()> {
    if results.len() == 1 {
        transition::from_e2e_result(
            target_root,
            state,
            &results[0],
            transition::AttemptTransition::Append,
        )?;
        transition::complete_replay_if_ready(target_root, state)?;
        return Ok(());
    }
    let mut slices = Vec::new();
    let mut comparison_runs = std::iter::once(&state.active_slice)
        .chain(state.parked_slices.values())
        .filter_map(|slice| slice.comparison_run_id.clone())
        .collect::<Vec<_>>();
    for result in results {
        let mut selected = inventory::scoped(state, Some(&result.api.parse()?))?;
        if let Some(slice) = prepared.and_then(|batch| batch.slices.get(&result.api)) {
            selected.active_slice = slice.clone();
        }
        transition::from_e2e_result(
            target_root,
            &mut selected,
            result,
            transition::AttemptTransition::Append,
        )?;
        if selected.phase == RewritePhase::ComparisonRecordingRequired {
            let excluded = comparison_runs
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let run_id = super::artifacts::allocate_run_id_excluding(
                target_root,
                crate::ManagedRecordingOperation::RecordComparison,
                &excluded,
            )?;
            selected.comparison_run_id = Some(run_id.clone());
            comparison_runs.push(run_id);
        }
        slices.push(selected.active_slice);
    }
    // Publish every method before choosing the next slice so a route worker sees
    // the whole failure set, and a passing sibling retains its own progress.
    for slice in slices {
        let item = state
            .api_inventory
            .iter_mut()
            .find(|item| item.api == slice.api)
            .unwrap();
        item.attempts = slice.attempts.len();
        item.e2e_current = slice.e2e_current;
        item.comparison_current = slice.comparison_current;
        item.status = if slice.phase == RewritePhase::SliceComplete {
            item.verified_target_fingerprint = slice.target_fingerprint.clone();
            RewriteApiStatus::Complete
        } else if slice.phase == RewritePhase::ImplementationRequired {
            RewriteApiStatus::ImplementationRequired
        } else {
            RewriteApiStatus::Pending
        };
        state.parked_slices.insert(slice.api.clone(), slice);
    }
    let path = api_selector::route(&state.api).to_string();
    let next = state
        .api_inventory
        .iter()
        .position(|item| {
            api_selector::route(&item.api) == path
                && item.status == RewriteApiStatus::ImplementationRequired
        })
        .or_else(|| {
            state
                .api_inventory
                .iter()
                .position(|item| !item.status.is_done())
        });
    if let Some(index) = next {
        inventory::resume_at(state, index)?;
    } else {
        let api = state.api.clone();
        let selected = state.parked_slices.remove(&api).unwrap();
        state.active_slice = selected;
        state.current_api_index = None;
    }
    state.bump();
    Ok(())
}

#[cfg(test)]
mod tests;
