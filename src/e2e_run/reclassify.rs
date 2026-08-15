use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::final_evidence::{
    build_final_evidence_from_current_report, refresh_background_evidence,
};
use super::model::{ActiveRunState, CaseStatus, RunStatus};
use super::progress::{
    ensure_replay_progress_revisable, revise_replay_progress, update_focused_index,
};
use super::result::{E2eApiRunResult, E2eVerificationGates, api_result};
use super::{E2eRunContext, config, store, support};
use crate::case_group::{load_case_group_inventory, load_complete_case_group_inventory};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FocusedBackgroundReclassification {
    pub recording_reused: bool,
    pub recording_run_id: String,
    pub rules_fingerprint: String,
    pub matched_unused_case: usize,
    pub matched_by_protocol: BTreeMap<String, usize>,
    pub remaining_dirty_cases: usize,
    pub attempt: u64,
    pub passed: bool,
    pub gates: E2eVerificationGates,
    #[serde(skip)]
    pub result: E2eApiRunResult,
}

pub(crate) fn latest_focused_api(context: E2eRunContext) -> Result<Option<String>> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    if !layout.group_index_path.is_file() {
        return Ok(None);
    }
    let inventory = load_case_group_inventory(&layout.group_index_path, &layout.case_source)?;
    let mut latest = None::<(u64, String)>;
    for group in inventory.groups {
        let state_path = layout
            .run_root
            .join("focused")
            .join(support::api_directory(&group.group_id))
            .join("latest/state.yaml");
        if !state_path.is_file() {
            continue;
        }
        let state: ActiveRunState = store::read_yaml(&state_path)?;
        if !state.status.is_terminal() || state.case_source != layout.case_source {
            continue;
        }
        let candidate = (state.sequence, group.group_id);
        if latest
            .as_ref()
            .is_none_or(|current| candidate.0 > current.0)
        {
            latest = Some(candidate);
        }
    }
    Ok(latest.map(|(_, api)| api))
}

pub(crate) fn focused_background_reclassification_recovery_required(
    context: E2eRunContext,
    api: &str,
) -> Result<bool> {
    let (_, base_layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let state_path = base_layout
        .run_root
        .join("focused")
        .join(support::api_directory(api))
        .join("latest/state.yaml");
    if !state_path.is_file() {
        return Ok(false);
    }
    let state: ActiveRunState = store::read_yaml(&state_path)?;
    Ok(state.status.is_terminal()
        && dependency_view_is_clean(&state)
        && state
            .errors
            .iter()
            .any(|error| is_strict_dependency_finalize_error(error)))
}

pub(crate) fn ensure_focused_background_reclassification_revisable(
    context: E2eRunContext,
    api: &str,
) -> Result<()> {
    let (_, base_layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !base_layout.active_dir.exists(),
        "cannot reclassify dependency evidence while an E2E attempt is active"
    );
    let focused_root = base_layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !focused_root.join(".active").exists(),
        "cannot reclassify dependency evidence while focused API {api:?} is active"
    );
    let state_path = focused_root.join("latest/state.yaml");
    let state: ActiveRunState = store::read_yaml(&state_path)
        .with_context(|| format!("no finalized focused E2E state exists for API {api:?}"))?;
    ensure!(
        state.status.is_terminal(),
        "focused E2E evidence is not terminal"
    );
    ensure!(
        state.case_source == base_layout.case_source,
        "focused E2E evidence belongs to another case source"
    );
    let index =
        store::load_or_create_index(&base_layout, &base_layout.run_key, &base_layout.case_source)?;
    ensure_replay_progress_revisable(&base_layout.progress_path, &index, &state)
}

pub(crate) fn reclassify_focused_background_dependencies(
    context: E2eRunContext,
    api: &str,
) -> Result<FocusedBackgroundReclassification> {
    let (config, base_layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    ensure!(
        !base_layout.active_dir.exists(),
        "cannot reclassify dependency evidence while an E2E attempt is active"
    );
    let inventory =
        load_case_group_inventory(&base_layout.group_index_path, &base_layout.case_source)?;
    let inventory_complete =
        load_complete_case_group_inventory(&base_layout.group_index_path, &base_layout.case_source)
            .is_ok();
    let group = inventory
        .groups
        .iter()
        .find(|group| group.group_id == api)
        .with_context(|| format!("prepared API group not found: {api}"))?;
    let focused_root = base_layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !focused_root.join(".active").exists(),
        "cannot reclassify dependency evidence while focused API {api:?} is active"
    );
    let latest_dir = focused_root.join("latest");
    let state_path = latest_dir.join("state.yaml");
    let mut state: ActiveRunState = store::read_yaml(&state_path)
        .with_context(|| format!("no finalized focused E2E state exists for API {api:?}"))?;
    ensure!(
        state.status.is_terminal(),
        "focused E2E evidence is not terminal"
    );
    ensure!(
        state.case_source == base_layout.case_source,
        "focused E2E evidence belongs to another case source"
    );
    let mut index =
        store::load_or_create_index(&base_layout, &base_layout.run_key, &base_layout.case_source)?;
    ensure_replay_progress_revisable(&base_layout.progress_path, &index, &state)?;
    let previous_state = state.clone();

    let reclassified = refresh_background_evidence(&config, &state)?;
    for case in &mut state.cases {
        let dirty = reclassified
            .remaining_dirty_case_ids
            .contains(&case.case_id);
        case.replay_clean = Some(!dirty);
        case.status = if case.assertion_passed == Some(true) && !dirty {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
    }
    let mut focused_layout = base_layout.clone();
    focused_layout.run_root = focused_root;
    focused_layout.latest_dir = latest_dir.clone();
    focused_layout.active_dir = latest_dir;
    build_final_evidence_from_current_report(
        &config,
        &focused_layout,
        &crate::case_group::CaseGroupInventory {
            case_source: inventory.case_source.clone(),
            source_revision: inventory.source_revision.clone(),
            case_inventory_id: inventory.case_inventory_id.clone(),
            groups: vec![group.clone()],
        },
        &mut state,
    )?;
    clear_resolved_dependency_errors(&mut state);
    state.status = terminal_status(&state);
    store::write_yaml(&state_path, &state)?;

    update_focused_index(&mut index, &state, &inventory, inventory_complete);
    store::write_yaml(&base_layout.index_path, &index)?;
    revise_replay_progress(&base_layout.progress_path, &index, &previous_state, &state)?;
    let result = api_result(&focused_layout, &state, api, state.sequence);
    Ok(FocusedBackgroundReclassification {
        recording_reused: true,
        recording_run_id: state.run_key.clone(),
        rules_fingerprint: reclassified.rules_fingerprint,
        matched_unused_case: reclassified.matched_unused_case,
        matched_by_protocol: reclassified.by_protocol,
        remaining_dirty_cases: reclassified.remaining_dirty_case_ids.len(),
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        result,
    })
}

fn terminal_status(state: &ActiveRunState) -> RunStatus {
    if state
        .cases
        .iter()
        .all(|case| case.status == CaseStatus::Passed)
        && state.replay_finalized
        && state.aggregate_complete
        && state.aggregate_clean
        && state.apis.iter().all(|api| api.complete_pass)
        && state.errors.is_empty()
    {
        RunStatus::Successful
    } else {
        RunStatus::Failed
    }
}

fn clear_resolved_dependency_errors(state: &mut ActiveRunState) {
    let clean_case_ids = state
        .cases
        .iter()
        .filter(|case| case.replay_clean == Some(true))
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let dependency_view_clean = dependency_view_is_clean(state);
    clear_resolved_dependency_error_messages(
        &mut state.errors,
        &clean_case_ids,
        dependency_view_clean,
    );
}

fn clear_resolved_dependency_error_messages(
    errors: &mut Vec<String>,
    clean_case_ids: &BTreeSet<String>,
    dependency_view_clean: bool,
) {
    errors.retain(|error| {
        if is_clean_case_dependency_error(error, clean_case_ids) {
            return false;
        }
        !(dependency_view_clean && is_strict_dependency_finalize_error(error))
    });
}

fn dependency_view_is_clean(state: &ActiveRunState) -> bool {
    state.replay_finalized
        && state.aggregate_complete
        && state.aggregate_clean
        && state
            .cases
            .iter()
            .all(|case| case.replay_clean == Some(true))
}

fn is_clean_case_dependency_error(error: &str, clean_case_ids: &BTreeSet<String>) -> bool {
    let Some(rest) = error.strip_prefix("case ") else {
        return false;
    };
    let Some((case_id, _)) = rest.split_once(" replay evidence is dirty:") else {
        return false;
    };
    clean_case_ids.contains(case_id)
}

fn is_strict_dependency_finalize_error(error: &str) -> bool {
    error.starts_with(
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges;",
    )
}

#[cfg(test)]
mod tests;
