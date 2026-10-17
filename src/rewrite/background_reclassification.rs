use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::model::{RewriteApiStatus, RewritePhase, RewriteState};
use super::{inventory, transition};
use crate::E2eRunContext;
use crate::e2e_run::{
    FocusedBackgroundReclassification, focused_background_reclassification_pending,
    reclassify_focused_background_dependencies,
};

pub(super) fn required_action(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Option<super::model::RewriteAction>> {
    Ok(pending_api(target_root, state)?.map(|api| super::model::RewriteAction::AdvanceRequired {
        summary: format!(
            "reconcile shared process-owned dependency evidence for {} before resuming implementation",
            super::api_selector::public_api(&api)
        ),
        command: super::action::next_command(target_root),
        api: Some(super::api_selector::public_api(&api).into()),
        kind: super::model::RewriteAdvanceKind::ReclassifyDependencies,
    }))
}

pub(super) fn pending_api(target_root: &Path, state: &RewriteState) -> Result<Option<String>> {
    if state.revalidation_round.is_some() || state.case_pattern_identification.is_some() {
        return Ok(None);
    }
    for slice in std::iter::once(&state.active_slice).chain(state.parked_slices.values()) {
        if slice.phase != RewritePhase::ImplementationRequired
            || slice.active_issue.is_none()
            || slice.rule_plan.is_some()
            || slice.dependency_rule_plan.is_some()
            || slice.recorder_capture_plan.is_some()
            // An explicit unified apply requires genuine new Replay. A report
            // reclassification cannot consume that execution obligation.
            || slice.rule_replay_pending
            || slice
                .active_issue
                .as_ref()
                .is_some_and(|issue| issue.kind == super::model::RewriteIssueKind::TargetQuality)
            || super::regression_scope::is_skipped(state, &slice.api)
        {
            continue;
        }
        let (Some(case_source), Some(api)) = (&slice.case_source, &slice.group_id) else {
            continue;
        };
        if !case_source.is_dir() {
            continue;
        }
        if focused_background_reclassification_pending(
            E2eRunContext {
                target_root: target_root.into(),
                case_source: case_source.clone(),
                run_key: None,
            },
            api,
        )? {
            return Ok(Some(slice.api.clone()));
        }
    }
    Ok(None)
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    owner_api: &str,
) -> Result<Value> {
    let owner = inventory::scoped(state, Some(&owner_api.parse()?))?;
    let case_source = owner
        .case_source
        .clone()
        .context("rewrite workflow has no case source to reclassify")?;
    let api = owner
        .group_id
        .clone()
        .context("rewrite workflow has no focused API to reclassify")?;
    let reclassification: FocusedBackgroundReclassification =
        reclassify_focused_background_dependencies(
            E2eRunContext {
                target_root: target_root.to_path_buf(),
                case_source,
                run_key: None,
            },
            &api,
        )?;
    let mut owner_updated = false;
    // Apply after the owner's temporary slice selection has been restored. The
    // real active method can itself be a sibling of a parked plan owner.
    for result in &reclassification.results {
        if result.api != state.api && !state.parked_slices.contains_key(&result.api) {
            continue;
        }
        let selected = inventory::scoped(state, Some(&result.api.parse()?))?;
        let matches_attempt = selected.case_source == owner.case_source
            && selected.group_id.as_deref() == Some(result.api.as_str())
            && selected
                .attempts
                .last()
                .is_some_and(|attempt| attempt.attempt == result.attempt)
            && matches!(
                selected.phase,
                RewritePhase::ImplementationRequired | RewritePhase::SliceComplete
            )
            && !selected
                .active_issue
                .as_ref()
                .is_some_and(|issue| issue.kind == super::model::RewriteIssueKind::TargetQuality);
        if !matches_attempt {
            continue;
        }
        inventory::with_slice_mut(state, &result.api, |selected| {
            transition::from_e2e_result(
                target_root,
                selected,
                result,
                transition::AttemptTransition::ReclassifyCurrent,
            )
        })?;
        let updated = inventory::scoped(state, Some(&result.api.parse()?))?;
        let active = state.api == result.api;
        if let Some(item) = state
            .api_inventory
            .iter_mut()
            .find(|item| item.api == result.api)
        {
            item.attempts = updated.attempts.len();
            item.e2e_current = updated.e2e_current;
            item.status = if active {
                RewriteApiStatus::Active
            } else if updated.phase == RewritePhase::SliceComplete {
                RewriteApiStatus::Complete
            } else if updated.phase == RewritePhase::ApiPending {
                RewriteApiStatus::Pending
            } else {
                RewriteApiStatus::ImplementationRequired
            };
            if updated.e2e_current {
                item.verified_target_fingerprint = updated.target_fingerprint.clone();
            }
        }
        owner_updated |= result.api == owner_api;
    }
    ensure!(
        owner_updated,
        "focused reclassification belongs to a different coordinator attempt"
    );
    Ok(serde_json::to_value(reclassification)?)
}

#[cfg(test)]
mod tests;
