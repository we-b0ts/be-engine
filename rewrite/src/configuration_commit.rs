//! Commit boundary for persistent configuration, independent of progress publication.
use std::path::Path;

use anyhow::Result;

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteInputRequiredReason, RewriteStatusReport,
};
use super::store::{RewriteLockState, RewriteStore};
use super::{action, traffic_operation};

pub(super) fn status(target_root: &Path) -> Result<Option<RewriteStatusReport>> {
    Ok(pending(target_root)?.map(|envelope| RewriteStatusReport {
        schema_version: envelope.schema_version,
        pending: envelope.pending,
        initialized: envelope.workflow.is_some(),
        workflow: envelope.workflow,
        api_inventory: envelope.api_inventory,
        latest_focused_e2e: envelope.latest_focused_e2e,
        // Uncommitted configuration cannot certify the next validation baseline.
        e2e_current: false,
        terminal_allowed: false,
        action: envelope.action,
    }))
}

pub(super) fn pending(target_root: &Path) -> Result<Option<RewriteActionEnvelope>> {
    let store = RewriteStore::new(target_root)?;
    if store.lock_state()? != RewriteLockState::Absent
        || super::execution::owned_by_other_process(target_root)?
        || !matches!(
            traffic_operation::state(target_root)?,
            traffic_operation::TrafficOperationState::Absent
        )
    {
        // Live work must finish; stale work must recover before asking for commits.
        return Ok(None);
    }
    pending_locked(target_root)
}

/// Also checked by `next` after acquiring its coordinator lock and before execution.
pub(super) fn pending_locked(target_root: &Path) -> Result<Option<RewriteActionEnvelope>> {
    let target_root = std::fs::canonicalize(target_root)?;
    let changes = crate::execution_identity::configuration_changes(&target_root)?;
    if changes.is_empty() {
        return Ok(None);
    }
    let summary: Vec<_> = changes
        .iter()
        .map(|change| format!("{} ({})", change.path, change.status))
        .collect();
    let action = RewriteAction::InputRequired {
        reason: RewriteInputRequiredReason::ConfigurationCommitRequired,
        summary: format!(
            "managed configuration has uncommitted changes: {}. The main orchestrator must review and commit the listed files in {} before dispatching workers or continuing verification, then rerun the original next command with the same scope and inputs. Review both staged and unstaged changes and any new files; staging alone does not complete this step. These are persistent configuration, not disposable runtime artifacts. Do not discard them or include unrelated changes. progress.yaml retains its final-delivery commit flow",
            summary.join(", "),
            target_root.display()
        ),
        required: changes.into_iter().map(|change| change.path).collect(),
        recording_input_diagnosis: None,
    };
    let mut envelope = match RewriteStore::new(&target_root)?.load()? {
        Some(state) => {
            if super::repository_analysis::publication_pending(&state)
                && let Some(analysis) =
                    super::repository_analysis::required_action(&target_root, &state)?
            {
                return Ok(Some(action::envelope(&target_root, &state, analysis)));
            }
            // Read-only expert assistance cannot change the validation baseline.
            // Its deadline remains actionable while configuration needs a commit.
            if let Some(expert) = super::expert::required_action(&target_root, &state, None) {
                return Ok(Some(action::envelope(&target_root, &state, expert)));
            }
            action::envelope(&target_root, &state, action)
        }
        None => {
            let mut envelope = action::input_required(&target_root);
            envelope.action = action;
            envelope
        }
    };
    envelope.pending = 1;
    envelope.terminal_allowed = false;
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests;
