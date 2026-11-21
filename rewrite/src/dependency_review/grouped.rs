//! Bounded group summaries and exact Source membership for analyst review.
use super::{AttributionReviewContext, model::SCHEMA, open};
use crate::{RewriteContext, action, model::RewriteState};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
use traffic_engine::attribution_review::{self, Group};
use traffic_rewrite_model::rewrite::dependency_review::model::{
    UnattributedGroup, UnattributedGroups,
};

const GROUP_PAGE: usize = 20;
const MEMBER_PAGE: usize = 100;
const SAMPLES: usize = 3;

pub(super) fn populate(
    root: &Path,
    state: &RewriteState,
    context: &mut AttributionReviewContext,
    offset: usize,
) -> Result<()> {
    let source = state
        .case_source
        .as_deref()
        .context("workflow has no Source recording")?;
    let groups = attribution_review::groups(source, &context.unattributed_exchange_ids)?;
    let total_groups = groups.len();
    let next_offset = offset.saturating_add(GROUP_PAGE);
    context.unattributed = UnattributedGroups {
        total_exchanges: context.unattributed_exchange_ids.len(),
        total_groups,
        groups: groups
            .into_iter()
            .skip(offset)
            .take(GROUP_PAGE)
            .map(|group| {
                let members_command =
                    members_command(root, state, &context.source_inventory_id, &group, 0);
                UnattributedGroup {
                    id: group.id,
                    shape: group.shape,
                    count: group.members.len(),
                    sample_exchange_ids: group.members.into_iter().take(SAMPLES).collect(),
                    members_command,
                }
            })
            .collect(),
        next_command: (next_offset < total_groups).then(|| {
            action::command(
                root,
                vec![
                    "dependency-attribution".into(),
                    "context".into(),
                    "--offset".into(),
                    next_offset.to_string(),
                ],
                vec![],
            )
        }),
    };
    Ok(())
}

pub fn dependency_attribution_group(
    context: RewriteContext,
    group: &str,
    inventory: &str,
    revision: u64,
    offset: usize,
) -> Result<Value> {
    let (root, store) = open(&context.target_root)?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let (identity, ids) = super::analysis::review_inventory(&root, &state)?;
    ensure!(
        identity == inventory && state.dependency_review.revision == revision,
        "attribution inventory or revision changed; obtain fresh context before continuing pagination"
    );
    let source = state
        .case_source
        .as_deref()
        .context("workflow has no Source recording")?;
    let group = attribution_review::groups(source, &ids)?
        .into_iter()
        .find(|candidate| candidate.id == group)
        .context("group is outside current unattributed review")?;
    let next_offset = offset.saturating_add(MEMBER_PAGE);
    let next = (next_offset < group.members.len())
        .then(|| members_command(&root, &state, &identity, &group, next_offset));
    Ok(json!({
        "schema": SCHEMA,
        "recording_run_id": state.recording_run_id,
        "source_inventory_id": identity,
        "revision": revision,
        "group": group.id,
        "shape": group.shape,
        "count": group.members.len(),
        "source_exchange_ids": group.members.into_iter().skip(offset).take(MEMBER_PAGE).collect::<Vec<_>>(),
        "next_command": next,
    }))
}

fn members_command(
    root: &Path,
    state: &RewriteState,
    inventory: &str,
    group: &Group,
    offset: usize,
) -> crate::model::RewriteCommandSpec {
    action::command(
        root,
        vec![
            "dependency-attribution".into(),
            "group".into(),
            "--group".into(),
            group.id.clone(),
            "--inventory".into(),
            inventory.into(),
            "--revision".into(),
            state.dependency_review.revision.to_string(),
            "--offset".into(),
            offset.to_string(),
        ],
        vec![],
    )
}
