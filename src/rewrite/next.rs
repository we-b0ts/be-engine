//! Execution of the selected step, optionally continuing passes and unfinished rounds.
//! Selection, priorities and gates remain with the existing action and advance owners.
use std::future::Future;

use anyhow::Result;

use super::advance::{AdvanceResult, advance_rewrite};
use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteAdvanceKind, RewriteExecutionMode,
};
use super::{RewriteContext, RewriteNextOptions, configuration_commit, execution};

pub(super) fn mode(options: &RewriteNextOptions) -> Result<RewriteExecutionMode> {
    Ok(
        if options.api.is_none()
            && options.source_route.is_none()
            && crate::config::regression::RegressionScope::load(&options.target_root)?.auto_next
        {
            RewriteExecutionMode::AutoNext
        } else {
            RewriteExecutionMode::Single
        },
    )
}

pub(super) fn selected_api(action: &RewriteAction) -> Result<Option<super::RewriteApiSelector>> {
    match action {
        RewriteAction::AdvanceRequired { api, .. } => api.as_deref().map(str::parse).transpose(),
        _ => Ok(None),
    }
}

pub async fn next_rewrite(options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    let mode = mode(&options)?;
    run_selected(options, mode).await
}

pub(super) async fn run_selected(
    options: RewriteNextOptions,
    mode: RewriteExecutionMode,
) -> Result<RewriteActionEnvelope> {
    run_steps(options, mode, step).await
}

async fn step(mut options: RewriteNextOptions) -> Result<AdvanceResult> {
    let target_root = options.target_root.clone();
    if let Some(envelope) = super::purpose::pending(&target_root)? {
        return Ok(AdvanceResult::without_replay(envelope));
    }
    if let Some(envelope) = configuration_commit::pending(&target_root)? {
        return Ok(AdvanceResult::without_replay(envelope));
    }
    if options.api.is_none() && options.source_route.is_none() {
        let status = super::status_rewrite(RewriteContext {
            target_root: target_root.clone(),
        })?;
        if status.initialized {
            if matches!(status.action, RewriteAction::AdvanceRequired { .. }) {
                options.api = selected_api(&status.action)?;
            } else {
                return Ok(AdvanceResult::without_replay(execution::from_status(
                    status,
                )));
            }
        }
    }
    execution::update_next_scope(&options)?;
    let mut result = advance_rewrite(options).await?;
    // A transition can persist configuration; surface its commit gate immediately.
    if let Some(envelope) = configuration_commit::pending(&target_root)? {
        result.envelope = envelope;
    }
    Ok(result)
}

async fn run_steps<F, Fut>(
    mut options: RewriteNextOptions,
    mode: RewriteExecutionMode,
    mut execute_step: F,
) -> Result<RewriteActionEnvelope>
where
    F: FnMut(RewriteNextOptions) -> Fut,
    Fut: Future<Output = Result<AdvanceResult>>,
{
    loop {
        let result = execute_step(options.clone()).await?;
        // Inspect newly published plans after every completed step, including
        // failed comparisons. The replay transaction may have started before
        // these independent plan events existed.
        let current = super::store::RewriteStore::new(&options.target_root)?.load()?;
        if let Some(state) = current.as_ref()
            && let Some(plan) = super::rule_plans::idle_action(&options.target_root, state)?
        {
            return Ok(super::action::envelope(&options.target_root, state, plan));
        }
        let group_continues = current
            .as_ref()
            .is_some_and(|state| state.implementers.is_some() && state.group_replay.is_some());
        if !result.replay_can_continue || mode != RewriteExecutionMode::AutoNext && !group_continues
        {
            return Ok(result.envelope);
        }
        // The previous atomic step has released its workflow lock and traffic lease.
        // Our own operation marker must not hide normal integration/review priorities.
        let status = super::status_rewrite(RewriteContext {
            target_root: options.target_root.clone(),
        })?;
        if (!group_continues
            && !crate::config::regression::RegressionScope::load(&options.target_root)?.auto_next)
            || !matches!(
                status.action,
                RewriteAction::AdvanceRequired {
                    kind: RewriteAdvanceKind::Replay,
                    ..
                }
            )
        {
            return Ok(execution::from_status(status));
        }
        options.api = selected_api(&status.action)?;
        options.source_route = None;
    }
}

#[cfg(test)]
mod tests;
