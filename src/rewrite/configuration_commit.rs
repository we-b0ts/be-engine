//! Commit boundary for persistent configuration, independent of progress publication.
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteInputRequiredReason, RewriteStatusReport,
};
use super::store::{RewriteLockState, RewriteStore};
use super::{RewriteNextOptions, action, traffic_operation};

const CONFIGURATION_PATHS: &[&str] = &[
    ".traffic-e2e/project.yaml",
    ".traffic-e2e/source-traffic-policy.yaml",
    ".traffic-e2e/verification.yaml",
];

pub async fn next_rewrite(mut options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    let target_root = options.target_root.clone();
    if let Some(envelope) = pending(&target_root)? {
        return Ok(envelope);
    }
    if options.api.is_none() && options.process_output.is_none() && options.source_route.is_none() {
        let status = super::status_rewrite(super::RewriteContext {
            target_root: target_root.clone(),
        })?;
        if status.initialized {
            if let RewriteAction::AdvanceRequired { command, .. } = &status.action {
                // These command specs are engine-owned argv, never shell programs.
                for pair in command.argv.windows(2) {
                    if pair[0] == "--api" {
                        options.api = Some(pair[1].parse()?);
                    }
                    if pair[0] == "--process-output" {
                        options.process_output = Some(pair[1].clone());
                    }
                }
            } else {
                return Ok(super::execution::from_status(status));
            }
        }
    }
    let envelope = super::advance_rewrite(options).await?;
    // A transition may itself persist configuration (for example a source route).
    // Return the commit boundary before handing the next action to a worker.
    Ok(pending(&target_root)?.unwrap_or(envelope))
}

pub(super) fn status(target_root: &Path) -> Result<Option<RewriteStatusReport>> {
    Ok(pending(target_root)?.map(|envelope| RewriteStatusReport {
        schema_version: envelope.schema_version,
        pending: envelope.pending,
        initialized: envelope.workflow.is_some(),
        workflow: envelope.workflow,
        api_inventory: envelope.api_inventory,
        process_output_inventory: envelope.process_output_inventory,
        latest_focused_e2e: envelope.latest_focused_e2e,
        // Uncommitted configuration cannot certify the next validation baseline.
        e2e_current: false,
        comparison_current: false,
        terminal_allowed: false,
        action: envelope.action,
    }))
}

fn pending(target_root: &Path) -> Result<Option<RewriteActionEnvelope>> {
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
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(&target_root)
        .args([
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--no-renames",
            "--",
        ])
        .args(CONFIGURATION_PATHS)
        .output()
        .context("failed to inspect managed configuration changes")?;
    ensure!(
        output.status.success(),
        "cannot inspect managed configuration changes: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let changes = String::from_utf8(output.stdout)?;
    let mut required = Vec::new();
    let mut summary = Vec::new();
    for line in changes.lines() {
        let Some(path) = line.get(3..) else {
            anyhow::bail!("invalid Git configuration status");
        };
        ensure!(
            CONFIGURATION_PATHS.contains(&path),
            "unexpected configuration path {path:?}"
        );
        required.push(path.to_string());
        summary.push(format!("{} ({})", path, &line[..2]));
    }
    if required.is_empty() {
        return Ok(None);
    }
    let action = RewriteAction::InputRequired {
        reason: RewriteInputRequiredReason::ConfigurationCommitRequired,
        summary: format!(
            "managed configuration has uncommitted changes: {}. The main orchestrator must review and commit the listed files in {} before dispatching workers or continuing verification, then rerun the original next command with the same scope and inputs. Review both staged and unstaged changes and any new files; staging alone does not complete this step. These are persistent configuration, not disposable runtime artifacts. Do not discard them or include unrelated changes. progress.yaml retains its final-delivery commit flow",
            summary.join(", "),
            target_root.display()
        ),
        required,
    };
    let mut envelope = match RewriteStore::new(&target_root)?.load()? {
        Some(state) => action::envelope(&target_root, &state, action),
        None => {
            let mut envelope = action::input_required(&target_root);
            envelope.action = action;
            envelope
        }
    };
    envelope.terminal_allowed = false;
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests;
