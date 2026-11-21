//! Candidate identity and receipt admission. No quality commands run here.
use super::*;
use crate::worker::model::RewriteWorkerActivity;
pub(super) use traffic_rewrite_review::candidate::{
    checks_passed, context, fresh, head, same_repository, scan_base, validate, validate_accepted,
};

pub(super) fn handoff(
    state: &RewriteState,
    scope: Option<&RewriteWorkScope>,
    handoff_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(scope) = scope else {
        ensure!(handoff_id.is_none(), "handoff id requires a work scope");
        return Ok(None);
    };
    let scope = current_handoff_scope(state, scope)?;
    worker::ensure_scope_confirmed(state, &scope, "integration review").with_context(|| {
        format!(
            "integration handoff for {} is not confirmed; refresh inventory",
            scope.label()
        )
    })?;
    let observation = worker::runtime::observation(state, &scope).with_context(|| {
        format!(
            "integration review requires an accepted worker handoff for {}; refresh inventory",
            scope.label()
        )
    })?;
    ensure!(
        handoff_id.is_some()
            && observation.handoff_id.as_deref() == handoff_id
            && matches!(
                observation.activity,
                RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
            ),
        "integration review must match the accepted handoff and dispatch for {}; requested_handoff_id={handoff_id:?}, current_handoff_id={:?}, current_activity={:?}; refresh inventory and regenerate the selected batch; for a retained single-handoff command use the exact accepted handoff ID without expanding or shortening it",
        scope.label(),
        observation.handoff_id,
        observation.activity
    );
    Ok(Some(worker::dispatch_view(state, scope, None).dispatch_id))
}

pub(super) fn current_handoff_scope(
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Result<RewriteWorkScope> {
    let scope = super::super::api_selector::canonical_scope(state, scope);
    ensure!(
        worker::runtime::scopes(state).contains(&scope),
        "integration handoff scope {} is no longer eligible: it is skipped, completed or has no current implementation dispatch. Refresh inventory and rebuild the batch from current handoff identities; do not reset integrated handoffs",
        scope.label()
    );
    Ok(scope)
}

pub(super) fn batch_handoffs(
    state: &RewriteState,
    selections: &[IntegrationHandoffSelection],
) -> Result<Vec<IntegrationHandoffReview>> {
    use worker::model::RewriteWorkerCoverageState as Coverage;

    let mut seen = std::collections::BTreeSet::new();
    let mut has_pending_handoff = false;
    let handoffs = selections
        .iter()
        .map(|selection| {
            ensure!(
                matches!(selection.scope, RewriteWorkScope::Api { .. }),
                "batch integration currently supports API handoffs only"
            );
            // Bindings survive skip/completion. Validate the current scope
            // before coverage computes a dispatch from its active issue.
            let scope = current_handoff_scope(state, &selection.scope)?;
            ensure!(
                seen.insert(scope.binding_key()),
                "batch integration contains a duplicate work item: {}",
                scope.label()
            );
            let coverage = worker::runtime::coverage(state, &scope);
            ensure!(
                matches!(coverage, Coverage::IntegrationRequired | Coverage::VerificationRequired),
                "batch integration requires a current handoff_ready or integrated handoff for {}; current coverage is {coverage:?}. Refresh inventory and rebuild the batch from current handoff identities; do not reset integrated handoffs",
                scope.label()
            );
            has_pending_handoff |= coverage == Coverage::IntegrationRequired;
            let scoped = worker::runtime::scoped(state, &scope)?;
            ensure!(
                scoped.rule_plan.is_none()
                    && scoped.dependency_rule_plan.is_none()
                    && scoped.recorder_capture_plan.is_none(),
                "finish the pending rule or capture plan before batching {}",
                scope.label()
            );
            let dispatch_id = handoff(state, Some(&scope), Some(&selection.handoff_id))?
                .expect("batch handoff has a scope");
            Ok(IntegrationHandoffReview {
                scope,
                dispatch_id,
                handoff_id: selection.handoff_id.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        has_pending_handoff,
        "all selected handoffs are already integrated; refresh the complete candidate with review check --integration --worktree <integration-worktree> without --batch-handoffs, a scope or --handoff-id, then publish and use review accept --report <report>. Keep existing handoffs integrated"
    );
    Ok(handoffs)
}

fn require_published_head(
    root: &Path,
    report: &RewriteReviewReport,
    integration: &IntegrationReview,
) -> Result<()> {
    let published = head(root)?;
    if published == report.head_revision {
        return Ok(());
    }
    let recovery = if published == integration.canonical_base_revision {
        "reviewed candidate is not published; reconcile the assignment and canonical inputs, then fast-forward the canonical branch to the exact reviewed commit before retrying admission. Equal file content does not waive publication; do not rerun review check solely for this HEAD mismatch"
    } else {
        "canonical HEAD changed from the reviewed base; reconcile publication and return stale work to the integrator before retrying admission. Do not reset the canonical branch or repeat check/accept with unchanged inputs"
    };
    anyhow::bail!(
        "{recovery}; canonical_root={}, published_head={published}, reviewed_head={}, reviewed_canonical_base={}",
        root.display(),
        report.head_revision,
        integration.canonical_base_revision
    )
}

/// Called under the coordinator lock after publication. Only validates the
/// delivered receipt; returns the worker commit only for a nonempty integration.
/// Never executes review commands or writes worker state.
pub(crate) fn accept_locked(
    root: &Path,
    state: &mut RewriteState,
    path: &Path,
    expected_scope: Option<&RewriteWorkScope>,
    expected_handoff: Option<&str>,
) -> Result<Option<String>> {
    let mut report: RewriteReviewReport = read_json(path)?;
    let integration = report
        .integration
        .as_ref()
        .context("integrated delivery requires an integration review report")?;
    let dispatch = handoff(state, expected_scope, expected_handoff)?;
    if integration.handoffs.is_empty() {
        ensure!(
            report.scope.as_ref() == expected_scope
                && integration.handoff_id.as_deref() == expected_handoff,
            "integration report does not match the delivered scope and handoff"
        );
        ensure!(
            report.dispatch_id == dispatch,
            "integration report dispatch is stale"
        );
    } else {
        // A mixed batch binds retained deliveries as well as newly ready ones.
        // None may be superseded between review and candidate admission.
        for entry in &integration.handoffs {
            let dispatch = handoff(state, Some(&entry.scope), Some(&entry.handoff_id))?;
            ensure!(
                dispatch.as_deref() == Some(entry.dispatch_id.as_str()),
                "batch integration report dispatch is stale for {}; refresh inventory and review the current candidate again",
                entry.scope.label()
            );
        }
        let scope = expected_scope.context("batch integration requires a worker scope")?;
        let entry = integration
            .handoffs
            .iter()
            .find(|entry| {
                &entry.scope == scope && Some(entry.handoff_id.as_str()) == expected_handoff
            })
            .context("integration report does not contain the delivered handoff")?;
        ensure!(
            report.scope.is_none()
                && report.dispatch_id.is_none()
                && integration.handoff_id.is_none()
                && dispatch.as_deref() == Some(entry.dispatch_id.as_str()),
            "batch integration report dispatch is stale"
        );
    }
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    if report.pre_revalidation.is_some() && pre_revalidation::current(root, state) {
        fresh(root, root, state, &report, &project)?;
        checks_passed(root, &report, &project)?;
        source_diff::git_text(
            root,
            &["merge-base", "--is-ancestor", &report.head_revision, "HEAD"],
        )?;
        // An already-admitted candidate survives progress-only publication. A
        // repeated accept is a no-op and cannot reset its remaining API sweep.
        return Ok(None);
    }
    require_published_head(root, &report, integration)?;
    validate(root, root, state, &report, &project)?;
    source_diff::git_text(
        root,
        &[
            "merge-base",
            "--is-ancestor",
            &integration.canonical_base_revision,
            "HEAD",
        ],
    )
    .context("published candidate does not descend from its reviewed canonical base")?;
    let code_commit = if let Some(RewriteWorkScope::Api { api }) = expected_scope {
        let worker_report = state
            .worker_bindings
            .get(api)
            .and_then(|binding| binding.review_report.as_ref())
            .context("integrated API delivery requires its accepted worker review")?;
        let worker_changed = committed_changes(
            root,
            &worker_report.base_revision,
            &worker_report.head_revision,
        )?;
        let integrated_changed = committed_changes(
            root,
            &integration.canonical_base_revision,
            &report.head_revision,
        )?;
        (worker_changed && integrated_changed).then(|| worker_report.head_revision.clone())
    } else {
        None
    };
    report.accepted_target_fingerprint = Some(fingerprint::review_fingerprint(root)?);
    if report.pre_revalidation.is_some() {
        pre_revalidation::admit(root, state, &report)?;
    }
    write_json(&integrated_path(root), &report)?;
    // Admission remains mandatory even when a receipt is lost or old caches
    // are invalidated by rule/configuration changes.
    state.delivery_review_required = true;
    state.bump();
    Ok(code_commit)
}

fn committed_changes(root: &Path, base: &str, head: &str) -> Result<bool> {
    Ok(base != head
        && !source_diff::git_text(root, &["diff", "--name-only", base, head, "--", "."])?
            .trim()
            .is_empty())
}

pub fn accept(target_root: PathBuf, path: PathBuf) -> Result<crate::RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = store.lock()?;
    ensure!(
        matches!(
            crate::traffic_operation::state(&root)?,
            crate::traffic_operation::TrafficOperationState::Absent
        ),
        "review admission must wait for traffic verification"
    );
    let mut state = store.load()?.context("rewrite workflow is absent")?;
    accept_locked(&root, &mut state, &path, None, None)?;
    store.save(&state)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}
