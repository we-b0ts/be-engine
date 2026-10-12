use super::*;
use crate::rewrite::model::RewritePhase;

pub(super) fn reuse_evidence(
    canonical_root: &Path,
    root: &Path,
    state: &RewriteState,
    findings: &[ReviewFinding],
    evidence: &mut ReviewEvidence,
) -> Result<()> {
    let previous = read_json::<RewriteReviewReport>(&integrated_path(canonical_root)).ok();
    let reports = state
        .worker_bindings
        .values()
        .filter_map(|b| b.review_report.as_ref())
        .chain(previous.as_ref());
    for report in reports {
        if report.workflow_id != state.workflow_id || !evidence::reusable(root, report) {
            continue;
        }
        for item in &report.evidence.spawns {
            if findings.iter().any(|f| f.id == item.finding_id)
                && !evidence
                    .spawns
                    .iter()
                    .any(|e| e.finding_id == item.finding_id)
            {
                evidence.spawns.push(item.clone());
            }
        }
    }
    Ok(())
}

pub(super) fn current(root: &Path, state: &RewriteState) -> Result<Option<RewriteReviewReport>> {
    let path = integrated_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    let Ok(report) = read_json::<RewriteReviewReport>(&path) else {
        // A broken or incompatible receipt is unavailable for admission. Keep
        // status actionable so the integrator can replace it through review.
        return Ok(None);
    };
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let valid = if report.accepted_target_fingerprint.is_some() {
        candidate::validate_accepted(root, state, &report, &project).is_ok()
    } else {
        candidate::fresh(root, root, state, &report, &project).is_ok()
            && candidate::head(root).is_ok_and(|head| head == report.head_revision)
    };
    Ok(valid.then_some(report))
}

pub(in crate::rewrite) fn terminal_current(root: &Path, state: &RewriteState) -> bool {
    current(root, state)
        .ok()
        .flatten()
        .is_some_and(|report| report.accepted_target_fingerprint.is_some())
}

pub(in crate::rewrite) fn requires_delivery_review(root: &Path, state: &RewriteState) -> bool {
    if state.regression.is_some() {
        // Purpose entry trusts its pr_base snapshot, never a previous workflow's
        // receipt. New local/integrated changes still require delivery review.
        return !unchanged_purpose_baseline(root, state);
    }
    state.delivery_review_required
        || state.target_quality_fingerprint.is_some()
        || integrated_path(root).is_file()
}

fn unchanged_purpose_baseline(root: &Path, state: &RewriteState) -> bool {
    let Some(origin) = state.regression.as_ref() else {
        return false;
    };
    // Keep outstanding handoff and finding admission mandatory, including when
    // the candidate has not yet been published to the canonical worktree.
    if !state.source_review_rework.is_empty()
        || worker::runtime::scopes(state)
            .iter()
            .any(|scope| worker::runtime::acceptance_ready(state, scope))
    {
        return false;
    }
    fingerprint::matches_revision(root, &origin.base_revision).unwrap_or(false)
}

/// An unchanged purpose baseline needs no source receipt. Modified delivery
/// retains the ordinary exact-version receipt contract.
pub(in crate::rewrite) fn admission_current(root: &Path, state: &RewriteState) -> bool {
    unchanged_purpose_baseline(root, state) || terminal_current(root, state)
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    let terminal = state.phase == RewritePhase::SliceComplete
        && !state.api_inventory.is_empty()
        && state.api_inventory.iter().all(|a| a.status.is_done());
    let ready = super::super::rule_replay::any_ready(state)
        || super::super::engine_retry::any_pending(state)
        || worker::runtime::scopes(state)
            .iter()
            .any(|scope| worker::runtime::acceptance_ready(state, scope));
    let review_required = requires_delivery_review(root, state);
    let revalidation = review_required && (state.phase == RewritePhase::ApiPending);
    if !terminal && !ready && !revalidation && state.source_review_rework.is_empty() {
        return Ok(None);
    }
    let report = current(root, state)?;
    if admission_current(root, state) {
        return Ok(None);
    }
    if report.as_ref().is_some_and(|r| rework_pending(state, r)) {
        return Ok(Some(rework_wait(root)));
    }
    if !terminal && !ready && !revalidation {
        return Ok(None);
    }
    Ok(Some(review_action(root, report.as_ref())))
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod verification_tests;

/// Coordinator admission only. Missing or stale receipts return an integrator
/// assignment; status/next never execute quality commands themselves.
pub(in crate::rewrite) fn gate(
    root: &Path,
    state: &RewriteState,
    _pr_base: &str,
) -> Result<Option<RewriteAction>> {
    if admission_current(root, state) {
        return Ok(None);
    }
    let report = current(root, state)?;
    if report.as_ref().is_some_and(|r| rework_pending(state, r)) {
        return Ok(Some(rework_wait(root)));
    }
    Ok(Some(review_action(root, report.as_ref())))
}

fn rework_pending(state: &RewriteState, report: &RewriteReviewReport) -> bool {
    worker::runtime::scopes(state).iter().any(|scope| {
        !worker::runtime::acceptance_ready(state, scope)
            && state
                .source_review_rework
                .get(&scope.binding_key())
                .is_some_and(|route| {
                    // Unrelated integrations change the report fingerprint without
                    // changing the finding already assigned to this worker.
                    report
                        .findings
                        .iter()
                        .any(|f| route.findings.contains_key(&f.id))
                })
    })
}

pub(in crate::rewrite) fn is_rework_wait(action: &RewriteAction) -> bool {
    matches!(action, RewriteAction::WaitRequired { resource, .. } if resource == "source_review_rework")
}

fn rework_wait(root: &Path) -> RewriteAction {
    RewriteAction::WaitRequired {
        execution_mode: None,
        summary: "source findings are assigned to a worker; continue worker events and integration, then rerun integrated review after the corrected handoff".into(),
        resource: "source_review_rework".into(),
        requested_api: None, blocking_api: None, active_operation: None,
        retry_after_seconds: 30,
        status: action::status_command_for_api(root, None),
    }
}

pub(super) fn review_action(root: &Path, report: Option<&RewriteReviewReport>) -> RewriteAction {
    RewriteAction::SourceReviewRequired {
        summary: match report.map(|r| r.status) {
            Some(ReviewStatus::ChangesRequired) => "source review found code changes required; inspect review show and route each finding with review rework to its owning work item",
            Some(ReviewStatus::EvidenceRequired) => "inspect review show; investigate each spawn and rerun review check --evidence with startup/request ownership evidence",
            Some(ReviewStatus::Passed) => "publish the reviewed integration candidate and accept its complete quality receipt before advancing verification",
            _ => "refresh the global quality receipt: prepare the code integrator worktree at the current canonical commit, preserving unfinished work, and delegate commands.check to the code integrator without a scope, --handoff-id or --batch-handoffs. Complete review checks the whole candidate; receipt expiry does not undo existing handoff integrations. If no new changes are needed, review that exact commit without an empty merge. Otherwise publish the exact passing candidate, then execute commands.accept before advancing verification",
        }.into(),
        check: action::command(root, vec!["review".into(), "check".into(), "--integration".into()], vec!["BACKEND_REWRITE_REVIEW_WORKTREE".into()]),
        accept: action::command(root, vec!["review".into(), "accept".into()], vec!["BACKEND_REWRITE_REVIEW_REPORT".into()]),
        show: action::command(root, vec!["review".into(), "show".into()], Vec::new()),
        rework: action::command(root, vec!["review".into(), "rework".into()], vec!["BACKEND_REWRITE_REVIEW_FINDING".into(), "BACKEND_REWRITE_REVIEW_OWNER".into()]),
    }
}
