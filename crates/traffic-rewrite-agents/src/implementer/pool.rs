//! Stable implementer slots derived from the adopted analyst grouping catalog.
use super::model::ImplementerPool;
use crate::model::RewriteState;
use anyhow::{Result, ensure};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub fn worktree(root: &Path, slot: usize) -> PathBuf {
    root.join(".traffic-e2e/local/rewrite-worktrees")
        .join(format!("api-implementer-{slot}"))
}

pub fn mapped_pool(state: &RewriteState) -> Result<Option<ImplementerPool>> {
    let Some(mut pool) = state.implementers.clone() else {
        return Ok(None);
    };
    ensure!(
        pool.effective_max_implementers > 0,
        "max_implementers must be positive"
    );
    if let Some(analysis) = &state.repository_analysis {
        let groups = state
            .api_inventory
            .iter()
            .filter(|item| !traffic_rewrite_model::rewrite::inventory::is_skipped(state, &item.api))
            .filter_map(|item| {
                analysis
                    .api_groups
                    .get(crate::api_selector::public_api(&item.api))
            })
            .collect::<BTreeSet<_>>();
        for group in groups {
            if !pool.group_slots.contains_key(group) {
                pool.group_slots.insert(
                    group.clone(),
                    pool.next_group_slot % pool.effective_max_implementers,
                );
                pool.next_group_slot = pool
                    .next_group_slot
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("implementer group mapping counter overflow"))?;
            }
        }
    }
    Ok(Some(pool))
}

pub fn refresh(state: &mut RewriteState) -> Result<bool> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(false);
    };
    let changed = state
        .implementers
        .as_ref()
        .is_none_or(|old| old.group_slots != pool.group_slots);
    if changed {
        state.implementers = Some(pool);
    }
    Ok(changed)
}
