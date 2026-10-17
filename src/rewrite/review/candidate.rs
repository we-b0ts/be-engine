//! Candidate identity and receipt admission. No quality commands run here.
use super::*;
use crate::e2e_run::ResolvedProjectConfig;
use crate::rewrite::worker::model::RewriteWorkerActivity;

pub(super) fn same_repository(root: &Path, worktree: &Path) -> Result<()> {
    let common = |path: &Path| -> Result<PathBuf> {
        Ok(fs::canonicalize(
            source_diff::git_text(
                path,
                &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            )?
            .trim(),
        )?)
    };
    ensure!(
        common(root)? == common(worktree)?,
        "review worktree belongs to another repository"
    );
    Ok(())
}

pub(super) fn head(root: &Path) -> Result<String> {
    Ok(source_diff::git_text(root, &["rev-parse", "HEAD"])?
        .trim()
        .into())
}

pub(super) fn scan_base(root: &Path, pr_base: &str) -> Result<String> {
    let base = source_diff::resolve_pr_base(root, pr_base)?;
    Ok(source_diff::git_text(root, &["merge-base", "HEAD", &base])?
        .trim()
        .into())
}

pub(super) fn context(root: &Path, project: &ResolvedProjectConfig) -> Result<String> {
    Ok(fingerprint::id(&[
        "review-validation-context-v1",
        &crate::rewrite::quality::policy_fingerprint()?,
        &project.pr_base,
        &serde_json::to_string(&project.managed_paths)?,
        &crate::startup::startup_snapshot_revision(root)?,
        &crate::startup::startup_environment_revision(root)?,
    ]))
}

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

pub(super) fn fresh(
    root: &Path,
    code_root: &Path,
    state: &RewriteState,
    report: &RewriteReviewReport,
    project: &ResolvedProjectConfig,
) -> Result<()> {
    let validation = report
        .validation
        .as_ref()
        .context("legacy review has no complete quality receipt; rerun review check")?;
    ensure!(
        report.schema_version
            == if report
                .integration
                .as_ref()
                .is_some_and(|value| !value.handoffs.is_empty())
            {
                3
            } else {
                2
            }
            && report.rules_version == RULE_VERSION
            && report.workflow_id == state.workflow_id
            && validation.recording_run_id == state.recording_run_id
            && validation.canonical_root == root,
        "review workflow, recording or rules changed; rerun review check"
    );
    ensure!(
        validation.code_fingerprint == fingerprint::code_fingerprint(code_root)?,
        "code changed after review; rerun review check"
    );
    ensure!(
        validation.context_fingerprint == context(root, project)?
            && validation.scan_base_revision == scan_base(code_root, &project.pr_base)?,
        "review configuration, base or canonical inputs changed; rerun review check"
    );
    if let Some(binding) = report.pre_revalidation.as_ref() {
        ensure!(
            validation.final_inputs_fingerprint.as_ref()
                == Some(&pre_revalidation::input_fingerprint(code_root)?),
            "Cargo or toolchain inputs changed after final review; rerun review check --pre-revalidation"
        );
        ensure!(
            binding == &pre_revalidation::context(root, state)?,
            "final review scope, recording or policy changed; rerun review check --pre-revalidation"
        );
    }
    Ok(())
}

pub(super) fn validate(
    root: &Path,
    code_root: &Path,
    state: &RewriteState,
    report: &RewriteReviewReport,
    project: &ResolvedProjectConfig,
) -> Result<()> {
    fresh(root, code_root, state, report, project)?;
    ensure!(
        report.head_revision == head(code_root)?,
        "commit changed after review; rerun review check"
    );
    checks_passed(code_root, report, project)
}

pub(super) fn validate_accepted(
    root: &Path,
    state: &RewriteState,
    report: &RewriteReviewReport,
    project: &ResolvedProjectConfig,
) -> Result<()> {
    ensure!(
        report.integration.is_some(),
        "accepted review requires a complete integration receipt; rerun integration review"
    );
    fresh(root, root, state, report, project)?;
    ensure!(
        report.accepted_target_fingerprint.as_deref()
            == Some(fingerprint::review_fingerprint(root)?.as_str()),
        "accepted review content or inputs changed"
    );
    source_diff::git_text(
        root,
        &["merge-base", "--is-ancestor", &report.head_revision, "HEAD"],
    )
    .context("accepted review commit is not an ancestor of the published target")?;
    ensure!(
        crate::rewrite::quality::source_evidence_unchanged(root, &report.head_revision)?,
        "source-evidence commit trailers changed after review; rerun review check"
    );
    checks_passed(root, report, project)
}

pub(super) fn checks_passed(
    code_root: &Path,
    report: &RewriteReviewReport,
    project: &ResolvedProjectConfig,
) -> Result<()> {
    ensure!(
        report.status == ReviewStatus::Passed,
        "review did not pass; fix the delivery and rerun review check"
    );
    let quality = report
        .quality
        .as_ref()
        .context("review lacks mandatory quality checks")?;
    if report.pre_revalidation.is_some() {
        pre_revalidation::ensure_committed(code_root)?;
        ensure!(report.integration.is_some() && report.scope.is_none()
            && report.integration.as_ref().is_some_and(|review| review.handoff_id.is_none() && review.handoffs.is_empty()),
            "final review must cover the global integration candidate");
        quality.ensure_pre_revalidation(code_root, &project.managed_paths)?;
    } else if report.integration.is_some() {
        quality.ensure_passed()?;
    } else {
        quality.ensure_passed_for(crate::rewrite::quality::QualityScope::Worker)?;
    }
    let (status, _) = evidence::evaluate(code_root, &report.findings, &report.evidence)?;
    ensure!(
        status == ReviewStatus::Passed,
        "review source evidence is incomplete"
    );
    Ok(())
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
pub(in crate::rewrite) fn accept_locked(
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

pub fn accept(
    target_root: PathBuf,
    path: PathBuf,
) -> Result<crate::rewrite::RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = store.lock()?;
    ensure!(
        matches!(
            crate::rewrite::traffic_operation::state(&root)?,
            crate::rewrite::traffic_operation::TrafficOperationState::Absent
        ),
        "review admission must wait for traffic verification"
    );
    let mut state = store.load()?.context("rewrite workflow is absent")?;
    accept_locked(&root, &mut state, &path, None, None)?;
    store.save(&state)?;
    drop(lock);
    worker::runtime::current_envelope(&root)
}
