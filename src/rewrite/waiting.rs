//! Bounded, read-only waiting. Task-runtime observations still come from the
//! coordinator; the engine cannot inspect or invent an external worker state.
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::model::{RewriteAction, RewriteActionEnvelope, RewriteCommandSpec};
use super::{RewriteContext, action, execution, status_rewrite};

#[derive(Debug, Clone)]
pub struct RewriteWaitOptions {
    pub target_root: PathBuf,
    pub seconds: u64,
}

pub(super) fn command(status: &RewriteCommandSpec, seconds: u64) -> RewriteCommandSpec {
    action::command(
        &status.cwd,
        vec![
            "wait".into(),
            "--seconds".into(),
            seconds.clamp(1, 30).to_string(),
        ],
        Vec::new(),
    )
}

pub async fn wait(options: RewriteWaitOptions) -> Result<RewriteActionEnvelope> {
    ensure!(
        (1..=30).contains(&options.seconds),
        "wait --seconds must be between 1 and 30"
    );
    let context = || RewriteContext {
        target_root: options.target_root.clone(),
    };
    let mut status = status_rewrite(context())?;
    let initial = serde_json::to_value(&status)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(options.seconds);
    while matches!(
        status.action,
        RewriteAction::WaitRequired { .. }
            | RewriteAction::RecordingInProgress { .. }
            | RewriteAction::RecordingRefreshPending { .. }
    ) {
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_secs(1)).min(deadline),
        )
        .await;
        status = status_rewrite(context())?;
        if tokio::time::Instant::now() >= deadline || serde_json::to_value(&status)? != initial {
            break;
        }
    }
    let mut envelope = execution::from_status(status);
    if envelope.terminal_allowed || matches!(envelope.action, RewriteAction::Blocked { .. }) {
        return Ok(envelope);
    }
    let root = std::fs::canonicalize(&options.target_root)?;
    envelope.action = RewriteAction::WorkerEventsRequired {
        summary: "inspect available task-runtime worker completion, failure and interruption events; report actual changes with their original dispatch and handoff identities, then execute commands.status. Use commands.inventory only to recover bindings. Do not re-report every running worker or infer liveness from historical dispatch; fifteen-minute status checks remain engine-scheduled".into(),
        inventory: action::command(&root, vec!["inventory".into()], Vec::new()),
        status: action::status_command_for_api(&root, None),
    };
    envelope.pending = envelope.pending.max(1);
    Ok(envelope)
}
