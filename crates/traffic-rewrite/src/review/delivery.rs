//! Commit and dispatch admission without source review or repository checks.
//!
//! Keep the existing persisted receipt envelope so outstanding deliveries remain
//! readable. Identity-only receipts never authorize final revalidation.
use super::*;

fn snapshot(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
    worktree: &Path,
    commit: &str,
    handoff: Option<&str>,
) -> Result<RewriteReviewReport> {
    ensure!(
        candidate::head(worktree)? == commit,
        "delivery commit must equal the published candidate HEAD or registered worker HEAD"
    );
    ensure!(
        fingerprint::matches_revision(worktree, commit)?,
        "commit target and managed code before delivering it"
    );
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let report = check_candidate(
        root,
        &project,
        state,
        RewriteReviewOptions {
            target_root: root.into(),
            worktree: Some(worktree.into()),
            scope: Some(scope.clone()),
            evidence: None,
            integration: handoff.is_some(),
            quality_check: None,
            handoff_id: handoff.map(str::to_owned),
            hardcode_ai_verified: Vec::new(),
        },
        None,
        false,
    )?;
    ensure!(
        report.head_revision == commit && fingerprint::matches_revision(worktree, commit)?,
        "delivery code or HEAD changed while capturing its identity"
    );
    Ok(report)
}

pub(crate) fn worker(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
    commit: &str,
) -> Result<RewriteReviewReport> {
    let worktree = &assignment(state, scope)?.worktree;
    snapshot(root, state, scope, worktree, commit, None)
}

/// The coordinator calls this only after publishing the integrator's exact
/// candidate. Capturing identity is part of admission, not an integrator check.
pub(crate) fn integrate(
    root: &Path,
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    handoff: &str,
    commit: &str,
) -> Result<Option<String>> {
    candidate::handoff(state, Some(scope), Some(handoff))?;
    let worker = state.worker_bindings[&scope.binding_key()]
        .review_report
        .as_ref()
        .context("integration requires the original frozen worker delivery")?;
    let base = worker.base_revision.clone();
    source_diff::git_text(root, &["merge-base", "--is-ancestor", &base, commit])
        .context("published integration must descend from the worker's dispatch base")?;
    let mut report = snapshot(root, state, scope, root, commit, Some(handoff))?;
    // The canonical checkout has already been published. Retain the original
    // dispatch base for meaningful nonempty-delivery accounting.
    report.integration.as_mut().unwrap().canonical_base_revision = base;
    write_json(&report.report_path, &report)?;
    candidate::accept_locked(root, state, &report.report_path, Some(scope), Some(handoff))
}
