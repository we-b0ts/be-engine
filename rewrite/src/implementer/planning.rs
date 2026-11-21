use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;

use super::model::{ImplementerDispatch, ImplementerPoolView};
use crate::{
    action,
    model::{RewriteAction, RewriteState},
    worker,
};

use traffic_rewrite_agents::implementer::pool::mapped_pool;
pub(crate) use traffic_rewrite_agents::implementer::pool::refresh;

#[cfg(feature = "test-support")]
pub(crate) fn dispatch(
    root: &Path,
    state: &RewriteState,
    group: &str,
) -> Result<Option<ImplementerDispatch>> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let Some(&slot_id) = pool.group_slots.get(group) else {
        return Ok(None);
    };
    dispatch_for_slot(root, state, group, slot_id)
}

pub(super) fn dispatch_for_slot(
    root: &Path,
    state: &RewriteState,
    group: &str,
    slot_id: usize,
) -> Result<Option<ImplementerDispatch>> {
    let ready = worker::runtime::scopes(state)
        .into_iter()
        .filter(|scope| crate::group_replay::dispatch_ready(state, &scope.binding_key()));
    traffic_rewrite_agents::implementer::planning::dispatch_for_slot(
        root, state, group, slot_id, ready,
    )
}

pub(crate) fn action(root: &Path, state: &RewriteState) -> Result<Option<RewriteAction>> {
    let Some(pool) = mapped_pool(state)? else {
        return Ok(None);
    };
    let mut candidates = pool
        .group_slots
        .iter()
        .map(|(group, slot)| (group.clone(), *slot))
        .collect::<BTreeSet<_>>();
    for (&slot_id, slot) in &pool.slots {
        for task in slot.tasks.values() {
            candidates.insert((task.group_id.clone(), slot_id));
        }
    }
    for (group, slot_id) in candidates {
        if let Some(dispatch) = dispatch_for_slot(root, state, &group, slot_id)? {
            let mut argv = vec![
                "implementer".into(),
                "confirm".into(),
                "--slot".into(),
                dispatch.slot_id.to_string(),
                "--group".into(),
                group.clone(),
                "--dispatch-id".into(),
                dispatch.dispatch_id.clone(),
            ];
            let mut env = Vec::new();
            if let Some(handle) = &dispatch.agent_handle {
                argv.extend(["--agent-handle".into(), handle.clone()]);
            } else {
                env.push(worker::AGENT_HANDLE_ENV.into());
            }
            return Ok(Some(RewriteAction::ImplementerDispatchRequired {
                summary: format!(
                    "dispatch this exact API batch to {}; retain its worktree and process one API at a time; hand off any completed subset through implementer handoff",
                    dispatch.name
                ),
                confirm: action::command(root, argv, env),
                report: report_command(root, dispatch.slot_id, dispatch.agent_handle.as_deref()),
                dispatch,
            }));
        }
    }
    Ok(None)
}

pub(super) fn report_command(
    root: &Path,
    slot: usize,
    handle: Option<&str>,
) -> crate::RewriteCommandSpec {
    let mut argv = vec![
        "implementer".into(),
        "report".into(),
        "--slot".into(),
        slot.to_string(),
    ];
    let mut env = vec![
        "BACKEND_REWRITE_IMPLEMENTER_API".into(),
        "BACKEND_REWRITE_IMPLEMENTER_DISPATCH_ID".into(),
        "BACKEND_REWRITE_IMPLEMENTER_LEASE_GENERATION".into(),
        worker::runtime::ACTIVITY_ENV.into(),
    ];
    if let Some(handle) = handle {
        argv.extend(["--agent-handle".into(), handle.into()]);
    } else {
        env.push(worker::AGENT_HANDLE_ENV.into());
    }
    action::command(root, argv, env)
}

pub(crate) fn view(root: &Path, state: &RewriteState) -> Result<Option<ImplementerPoolView>> {
    traffic_rewrite_agents::implementer::planning::view(
        root,
        state,
        &worker::runtime::scopes(state),
        report_command,
    )
}
