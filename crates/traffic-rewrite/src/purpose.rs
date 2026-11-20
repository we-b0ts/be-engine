//! pr_base is an entry point, never authority to resume retained implementation work.
use super::{
    action,
    model::{RewriteAction, RewriteActionEnvelope, RewriteStatusReport},
    store::RewriteStore,
};
use anyhow::{Result, ensure};
use std::path::Path;

pub(super) fn base_branch(root: &Path) -> Result<Option<String>> {
    // Invalid/uncommitted configuration retains its existing repair/commit gate.
    // No purpose can be inferred until pr_base is available from valid configuration.
    let Ok((root, project)) = crate::e2e_run::resolve_project(root) else {
        return Ok(None);
    };
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()?;
    Ok(
        (output.status.success() && String::from_utf8(output.stdout)?.trim() == project.pr_base)
            .then_some(project.pr_base),
    )
}

pub(super) fn require_work_branch(root: &Path) -> Result<()> {
    ensure!(
        base_branch(root)?.is_none(),
        "pr_base requires purpose confirmation; execute backend-rewrite status before dispatching workers or starting traffic"
    );
    Ok(())
}

pub(super) fn pending(root: &Path) -> Result<Option<RewriteActionEnvelope>> {
    let Some(pr_base) = base_branch(root)? else {
        return Ok(None);
    };
    let root = std::fs::canonicalize(root)?;
    let mut envelope = action::input_required(&root);
    envelope.action = RewriteAction::PurposeRequired {
        summary: "Start a new regression run?".into(),
        pr_base,
        replay: action::command(
            &root,
            vec!["purpose".into(), "confirm".into(), "--user-approved".into()],
            vec![
                "BACKEND_REWRITE_SESSION_ACTIVE_AGENT_COUNT".into(),
                "BACKEND_REWRITE_SESSION_QUERY_COMMAND".into(),
                "BACKEND_REWRITE_SESSION_QUERY_AT".into(),
            ],
        ),
    };
    envelope.pending = 1;
    envelope.terminal_allowed = false;
    Ok(Some(envelope))
}

pub(super) fn status(root: &Path) -> Result<Option<RewriteStatusReport>> {
    Ok(pending(root)?.map(|e| RewriteStatusReport {
        schema_version: e.schema_version,
        pending: e.pending,
        initialized: RewriteStore::new(root).is_ok_and(|s| s.exists()),
        workflow: e.workflow,
        api_inventory: e.api_inventory,
        latest_focused_e2e: None,
        e2e_current: false,
        terminal_allowed: false,
        action: e.action,
    }))
}
