//! Select fresh repair inputs without promoting historical passes to fresh evidence.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::model::{ActiveRunState, RunLayout};
use crate::case_group::{CanonicalCaseGroup, CaseGroupInventory};

pub struct ReplayIteration {
    pub workflow_id: String,
    pub final_round: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CaseSelection {
    workflow_id: String,
    final_round: bool,
    #[serde(default)]
    replay_timing: Option<crate::replay::ReplayStreamTiming>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dependency_attribution_snapshot: Option<String>,
    #[serde(default = "default_stream_interval_cap_ms")]
    replay_interval_cap_ms: u64,
    groups: BTreeMap<String, GroupSelection>,
    pub(super) skipped_passed_case_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupSelection {
    inventory_id: String,
    case_ids: BTreeSet<String>,
}

fn default_stream_interval_cap_ms() -> u64 {
    crate::replay::DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS
}

impl CaseSelection {
    pub(super) fn validate_stream_timing(
        &self,
        config: &super::model::ResolvedProjectConfig,
    ) -> Result<()> {
        ensure!(
            self.replay_timing == config.replay_stream_timing
                && (self.replay_timing != Some(crate::replay::ReplayStreamTiming::Fast)
                    || self.replay_interval_cap_ms == config.replay_stream_interval_cap_ms),
            "Case selection stream timing differs from the resolved Replay runtime; start a fresh attempt"
        );
        Ok(())
    }

    pub(super) fn completed_workflow(&self) -> Result<&str> {
        ensure!(
            self.final_round
                && !self.workflow_id.is_empty()
                && self.skipped_passed_case_ids.is_empty(),
            "workflow certification requires a fresh final session without skipped historical passes"
        );
        Ok(&self.workflow_id)
    }

    pub(super) fn project(&mut self, api: &str) {
        self.groups.retain(|group, _| group == api);
        self.skipped_passed_case_ids.retain(|id| {
            self.groups
                .values()
                .any(|group| group.case_ids.contains(id))
        });
    }
}

pub(super) fn prepare(
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    iteration: Option<&ReplayIteration>,
) -> Result<Option<CaseSelection>> {
    let Some(iteration) = iteration else {
        return Ok(None);
    };
    let dependency_attribution_snapshot =
        if crate::dependency_index::recording::root(&inventory.case_source).is_some() {
            let (_, manifest) =
                crate::dependency_index::recording::manifest(&inventory.case_source)?;
            Some(
                crate::coordination::dependency_attribution_identity_for_source(
                    &layout.target_root,
                    &inventory.case_source,
                    &manifest.run_id,
                )?,
            )
        } else {
            None
        };
    let groups = inventory
        .groups
        .iter()
        .map(|group| {
            let selection = GroupSelection {
                inventory_id: group.case_inventory_id.clone(),
                case_ids: group
                    .cases
                    .iter()
                    .map(|case| case.case_id.clone())
                    .collect(),
            };
            (group.group_id.clone(), selection)
        })
        .collect();
    Ok(Some(CaseSelection {
        workflow_id: iteration.workflow_id.clone(),
        final_round: iteration.final_round,
        replay_timing: None,
        dependency_attribution_snapshot,
        replay_interval_cap_ms: default_stream_interval_cap_ms(),
        groups,
        skipped_passed_case_ids: BTreeSet::new(),
    }))
}

pub(super) fn validate_group(state: &ActiveRunState, group: &CanonicalCaseGroup) -> Result<()> {
    validate_membership(
        state,
        &group.group_id,
        &group.case_inventory_id,
        group.cases.iter().map(|case| case.case_id.as_str()),
    )
}

pub(super) fn validate_membership<'a>(
    state: &ActiveRunState,
    group_id: &str,
    inventory_id: &str,
    prepared_case_ids: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let expected: BTreeSet<_> = prepared_case_ids.collect();
    let selected: BTreeSet<_> = state
        .cases
        .iter()
        .filter(|case| case.group_id == group_id)
        .map(|case| case.case_id.as_str())
        .collect();
    let skipped = if let Some(selection) = &state.case_selection {
        let declared = selection.groups.get(group_id);
        ensure!(
            declared.is_some_and(|declared| {
                declared.inventory_id == inventory_id
                    && declared
                        .case_ids
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                        == expected
            }),
            "focused case selection has a different prepared API inventory"
        );
        let all_declared = selection
            .groups
            .values()
            .flat_map(|group| &group.case_ids)
            .collect::<BTreeSet<_>>();
        ensure!(
            selection
                .skipped_passed_case_ids
                .iter()
                .all(|id| all_declared.contains(id)),
            "focused case selection skips an unknown case"
        );
        ensure!(
            !selection.final_round || selection.skipped_passed_case_ids.is_empty(),
            "final Replay cannot skip previously passed cases"
        );
        selection
            .skipped_passed_case_ids
            .iter()
            .map(String::as_str)
            .filter(|id| expected.contains(id))
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    ensure!(
        !selected.is_empty()
            && selected.is_disjoint(&skipped)
            && selected.union(&skipped).copied().collect::<BTreeSet<_>>() == expected
            && state
                .cases
                .iter()
                .filter(|case| case.group_id == group_id)
                .count()
                == selected.len(),
        "focused attempt does not match the canonical API case inventory"
    );
    Ok(())
}

/// Retain the actual session membership when recovering or reclassifying evidence.
pub(super) fn restrict(inventory: &mut CaseGroupInventory, state: &ActiveRunState) -> Result<()> {
    for group in &mut inventory.groups {
        validate_group(state, group)?;
        group.cases.retain(|case| {
            state
                .cases
                .iter()
                .any(|selected| selected.case_id == case.case_id)
        });
    }
    Ok(())
}

pub(super) fn diagnosis(state: &ActiveRunState) -> Option<Value> {
    let selection = state.case_selection.as_ref()?;
    Some(json!({
        "mode":if selection.skipped_passed_case_ids.is_empty() {"full"} else {"failed_only"},
        "final_round":selection.final_round,
        "available":state.cases.len() + selection.skipped_passed_case_ids.len(),
        "selected":state.cases.len(),
        "skipped_previously_passed":selection.skipped_passed_case_ids.len(),
    }))
}

#[cfg(test)]
mod tests;
