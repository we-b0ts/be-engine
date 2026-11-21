//! Bounded, read-only waiting. Task-runtime observations still come from the
//! coordinator; the engine cannot inspect or invent an external worker state.
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, ensure};

use super::model::{RewriteAction, RewriteActionEnvelope};
use super::{RewriteContext, action, execution, status_rewrite};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(6);

#[derive(Debug, Clone)]
pub struct RewriteWaitOptions {
    pub target_root: PathBuf,
    pub seconds: u64,
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
    let initial = wake_snapshot(&status)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(options.seconds);
    while matches!(
        status.action,
        RewriteAction::WaitRequired { .. }
            | RewriteAction::RecordingInProgress { .. }
            | RewriteAction::RecordingRefreshPending { .. }
    ) {
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + STATUS_POLL_INTERVAL).min(deadline),
        )
        .await;
        status = status_rewrite(context())?;
        if tokio::time::Instant::now() >= deadline || wake_snapshot(&status)? != initial {
            break;
        }
    }
    let mut envelope = execution::from_status(status);
    if envelope.terminal_allowed
        || matches!(
            envelope.action,
            RewriteAction::Blocked { .. } | RewriteAction::PurposeRequired { .. }
        )
    {
        return Ok(envelope);
    }
    let root = std::fs::canonicalize(&options.target_root)?;
    envelope.action = RewriteAction::WorkerEventsRequired {
        summary: "must actually invoke built-in ListAgents (/list-agents) in Claude Code, or the available runtime equivalent, for all workers awaiting results, including parked work and retained API expert tasks. Follow expert close_required actions for already verified APIs; forward reports only for unfinished APIs and acknowledge delivery with the inventory expert command; never report expert activity as implementation-worker activity. Match bound identities, exclude unrelated peers, and resolve omitted or unclassified tasks through results or individual queries. Historical reports and absent stop events do not establish liveness. Report observations by agent_handle and deliveries with the original review report and handoff identity, then execute commands.status. Use commands.inventory to recover bindings or coverage; unknown activity is not running. Repeat this query pass after every wait; unchanged running reports need not be refreshed".into(),
        inventory: action::command(&root, vec!["inventory".into()], Vec::new()),
        status: action::status_command_for_api(&root, None),
    };
    envelope.pending = envelope.pending.max(1);
    Ok(envelope)
}

fn wake_snapshot(status: &super::model::RewriteStatusReport) -> Result<serde_json::Value> {
    Ok(normalize_wake_snapshot(serde_json::to_value(status)?))
}

fn normalize_wake_snapshot(mut snapshot: serde_json::Value) -> serde_json::Value {
    if let Some(action) = snapshot
        .get_mut("action")
        .and_then(serde_json::Value::as_object_mut)
    {
        action.remove("summary");
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_text_does_not_wake_wait_but_actionable_state_does() {
        assert_eq!(STATUS_POLL_INTERVAL, Duration::from_secs(6));
        let initial = serde_json::json!({
            "workflow": {"revision": 4},
            "action": {
                "kind": "wait_required",
                "summary": "replaying GET /api/teams (932/941)",
                "details": {"resource": "coordinator_operation"}
            }
        });
        let mut progress = initial.clone();
        progress["action"]["summary"] = "replaying GET /api/teams (933/941)".into();
        assert_eq!(
            normalize_wake_snapshot(initial.clone()),
            normalize_wake_snapshot(progress)
        );

        let mut actionable = initial.clone();
        actionable["action"]["details"]["resource"] = "worker_handoff".into();
        assert_ne!(
            normalize_wake_snapshot(initial),
            normalize_wake_snapshot(actionable)
        );
    }
}
