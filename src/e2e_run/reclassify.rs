use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::final_evidence::{
    apply_reclassified_case_outcomes, build_final_evidence_from_current_report,
    clear_resolved_dependency_errors, dependency_view_is_clean,
    is_strict_dependency_finalize_error, refresh_background_evidence,
};
use super::model::{ActiveRunState, CaseStatus, RunStatus};
use super::progress::update_focused_index;
use super::result::{E2eApiRunResult, E2eVerificationGates, api_result};
use super::{E2eRunContext, config, store, support};
use crate::case_group::{load_case_group_inventory, load_complete_case_group_inventory};

mod session;

/// Detect the old one-method publication bug without changing evidence in status.
pub(crate) fn focused_background_reclassification_pending(
    context: E2eRunContext,
    api: &str,
) -> Result<bool> {
    let (config, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let path = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api))
        .join("latest/state.yaml");
    if !path.is_file() || !layout.group_index_path.is_file() {
        return Ok(false);
    }
    if layout.active_dir.exists() || !store::focused_active_directories(&layout)?.is_empty() {
        return Ok(false);
    }
    let inventory = load_case_group_inventory(&layout.group_index_path, &layout.case_source)?;
    let members = session::members(&layout, &inventory, api)?;
    if session::pending(&layout, &members)? {
        return Ok(true);
    }
    let rules = crate::config::SourceTrafficPolicyConfig::load(&config.source_traffic_policy)?
        .process_owned_dependencies;
    let current = crate::verification_progress::fingerprint(&serde_json::to_vec(&rules)?);
    let mut fresh = false;
    let mut stale = false;
    for member in members {
        if !member.state.replay_report.is_file() {
            return Ok(false);
        }
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&member.state.replay_report)?)?;
        if report["background_reclassification"]["rules_fingerprint"].as_str()
            == Some(current.as_str())
        {
            fresh = true;
        } else {
            stale = true;
        }
    }
    Ok(fresh && stale)
}

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
    pub updated_apis: Vec<String>,
    #[serde(skip)]
    pub result: E2eApiRunResult,
    #[serde(skip)]
    pub results: Vec<E2eApiRunResult>,
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
    let inventory =
        load_case_group_inventory(&base_layout.group_index_path, &base_layout.case_source)?;
    let members = session::members(&base_layout, &inventory, api)?;
    let index =
        store::load_or_create_index(&base_layout, &base_layout.run_key, &base_layout.case_source)?;
    session::preflight(&base_layout, &members, &index)?;
    Ok(())
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
    let mut members = session::members(&base_layout, &inventory, api)?;
    let original_index =
        store::load_or_create_index(&base_layout, &base_layout.run_key, &base_layout.case_source)?;
    let revision = session::preflight(&base_layout, &members, &original_index)?;
    session::begin(&base_layout, &revision)?;
    let mut index = revision.index.clone();
    let mut selected = None;
    let mut results = Vec::new();
    for member in &mut members {
        let reclassified = refresh_background_evidence(&config, &member.state, &inventory)?;
        apply_reclassified_case_outcomes(&mut member.state, &reclassified);
        let mut method_inventory = inventory.clone();
        method_inventory.groups = vec![member.group.clone()];
        build_final_evidence_from_current_report(
            &config,
            &member.layout,
            &method_inventory,
            &mut member.state,
        )?;
        clear_resolved_dependency_errors(&mut member.state);
        member.state.status = terminal_status(&member.state);
        update_focused_index(&mut index, &member.state, &inventory, inventory_complete);
        let result = api_result(
            &member.layout,
            &member.state,
            &member.group.group_id,
            member.state.sequence,
        );
        if member.group.group_id == api {
            selected = Some((reclassified, result.clone()));
        }
        results.push(result);
    }
    session::publish(&base_layout, &revision, &original_index, &index, &members)?;
    let (reclassified, result) = selected.context("requested method was not reclassified")?;
    Ok(FocusedBackgroundReclassification {
        recording_reused: true,
        recording_run_id: base_layout.run_key.clone(),
        rules_fingerprint: reclassified.rules_fingerprint,
        matched_unused_case: reclassified.matched_unused_case,
        matched_by_protocol: reclassified.by_protocol,
        remaining_dirty_cases: reclassified.remaining_dirty_case_ids.len(),
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        updated_apis: results.iter().map(|result| result.api.clone()).collect(),
        result,
        results,
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

#[cfg(test)]
mod tests;
