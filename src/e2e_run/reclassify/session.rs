//! Select exact session projections and retain the baseline for interrupted revisions.
use std::{fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::{
    case_selection,
    model::{ActiveRunState, RunIndex, RunLayout},
    progress, store, support,
};
use crate::case_group::{CanonicalCaseGroup, CaseGroupInventory};

pub(super) struct Member {
    pub group: CanonicalCaseGroup,
    pub layout: RunLayout,
    pub state: ActiveRunState,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Revision {
    pub index: RunIndex,
    pub previous: Vec<ActiveRunState>,
}

pub(super) fn revision_path(base: &RunLayout) -> PathBuf {
    base.run_root.join("focused-reclassification.pending.yaml")
}

pub(super) fn members(
    base: &RunLayout,
    inventory: &CaseGroupInventory,
    api: &str,
) -> Result<Vec<Member>> {
    ensure!(
        !base.active_dir.exists() && store::focused_active_directories(base)?.is_empty(),
        "cannot reclassify dependency evidence while an E2E attempt is active"
    );
    let primary_path = base
        .run_root
        .join("focused")
        .join(support::api_directory(api))
        .join("latest/state.yaml");
    let primary: ActiveRunState = store::read_yaml(&primary_path)
        .with_context(|| format!("no finalized focused E2E state exists for API {api:?}"))?;
    validate_primary(base, &primary)?;
    let mut selected = Vec::new();
    for group in &inventory.groups {
        let mut layout = base.clone();
        layout.run_root = base
            .run_root
            .join("focused")
            .join(support::api_directory(&group.group_id));
        layout.latest_dir = layout.run_root.join("latest");
        layout.active_dir = layout.latest_dir.clone();
        let path = layout.latest_dir.join("state.yaml");
        if !path.is_file() {
            continue;
        }
        let state: ActiveRunState = store::read_yaml(&path)?;
        if state.session_id != primary.session_id {
            continue;
        }
        validate_projection(
            &primary,
            &state,
            &group.group_id,
            group.cases.iter().map(|case| case.case_id.as_str()),
            &group.case_inventory_id,
        )?;
        let mut selected_group = group.clone();
        selected_group.cases.retain(|case| {
            state
                .cases
                .iter()
                .any(|selected| selected.case_id == case.case_id)
        });
        selected.push(Member {
            group: selected_group,
            layout,
            state,
        });
    }
    ensure!(
        selected.iter().any(|member| member.group.group_id == api),
        "prepared API group not found: {api}"
    );
    Ok(selected)
}

pub(super) fn validate_primary(base: &RunLayout, primary: &ActiveRunState) -> Result<()> {
    ensure!(
        primary.status.is_terminal(),
        "focused E2E evidence is not terminal"
    );
    ensure!(
        primary.case_source == base.case_source && primary.run_key == base.run_key,
        "focused E2E evidence belongs to another case source"
    );
    ensure!(
        primary.session_id.is_some(),
        "focused E2E evidence has no Replay session identity"
    );
    Ok(())
}

pub(super) fn validate_projection<'a>(
    primary: &ActiveRunState,
    state: &ActiveRunState,
    group_id: &str,
    prepared_case_ids: impl Iterator<Item = &'a str>,
    inventory_id: &str,
) -> Result<()> {
    ensure!(
        state.run_key == primary.run_key
            && state.sequence == primary.sequence
            && state.case_source == primary.case_source
            && state.case_inventory_id == primary.case_inventory_id
            && state.source_revision == primary.source_revision,
        "focused projections disagree on shared Replay session identity"
    );
    ensure!(
        state.status.is_terminal(),
        "shared Replay projection is not terminal"
    );
    ensure!(
        state.cases.iter().all(|case| case.group_id == group_id),
        "shared Replay projection does not match its prepared method inventory"
    );
    case_selection::validate_membership(state, group_id, inventory_id, prepared_case_ids)
        .context("shared Replay projection does not match its prepared method inventory")?;
    Ok(())
}

pub(super) fn preflight(
    base: &RunLayout,
    members: &[Member],
    index: &RunIndex,
) -> Result<Revision> {
    let path = revision_path(base);
    if !path.is_file() {
        for member in members {
            progress::ensure_replay_progress_revisable(&base.progress_path, index, &member.state)?;
        }
        return Ok(Revision {
            index: index.clone(),
            previous: members.iter().map(|member| member.state.clone()).collect(),
        });
    }
    let revision: Revision = store::read_yaml(&path)?;
    ensure!(
        revision.previous.len() == members.len(),
        "pending reclassification session membership changed"
    );
    for (previous, member) in revision.previous.iter().zip(members) {
        ensure!(
            previous.session_id == member.state.session_id
                && previous.sequence == member.state.sequence
                && previous.run_key == member.state.run_key
                && previous.case_source == member.state.case_source
                && previous.case_inventory_id == member.state.case_inventory_id
                && previous.cases.iter().map(|case| &case.case_id).eq(member
                    .state
                    .cases
                    .iter()
                    .map(|case| &case.case_id)),
            "pending reclassification would overwrite a different Replay attempt"
        );
        // A crash may leave either the baseline or the revised progress publication.
        progress::ensure_replay_progress_revisable(&base.progress_path, &revision.index, previous)
            .or_else(|_| {
                progress::ensure_replay_progress_revisable(
                    &base.progress_path,
                    index,
                    &member.state,
                )
            })?;
    }
    Ok(revision)
}

pub(super) fn begin(base: &RunLayout, revision: &Revision) -> Result<()> {
    if !revision_path(base).is_file() {
        store::write_yaml(&revision_path(base), revision)?;
    }
    Ok(())
}

pub(super) fn publish(
    base: &RunLayout,
    revision: &Revision,
    original_index: &RunIndex,
    index: &RunIndex,
    members: &[Member],
) -> Result<()> {
    let current = serde_json::to_value(original_index)?;
    ensure!(
        current == serde_json::to_value(&revision.index)?
            || current == serde_json::to_value(index)?,
        "replay progress index changed during pending session reclassification"
    );
    for member in members {
        store::write_yaml(&member.layout.latest_dir.join("state.yaml"), &member.state)?;
    }
    store::write_yaml(&base.index_path, index)?;
    for (previous, member) in revision.previous.iter().zip(members) {
        progress::revise_replay_progress(&base.progress_path, index, previous, &member.state)?;
    }
    fs::remove_file(revision_path(base))?;
    Ok(())
}
