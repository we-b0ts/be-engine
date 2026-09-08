use super::*;
use crate::rewrite::model::{RewriteApiStatus, RewritePhase};

pub(super) fn reuse_evidence(
    root: &Path,
    state: &RewriteState,
    findings: &[ReviewFinding],
    evidence: &mut ReviewEvidence,
) -> Result<()> {
    let previous = read_json::<RewriteReviewReport>(&integrated_path(root)).ok();
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
    let report: RewriteReviewReport = read_json(&path)?;
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let base_ref = source_diff::resolve_pr_base(root, &project.pr_base)?;
    let base = source_diff::git_text(root, &["merge-base", "HEAD", &base_ref])?;
    Ok((report.rules_version == RULE_VERSION
        && report.workflow_id == state.workflow_id
        && report.base_revision == base.trim()
        && report.target_fingerprint == fingerprint::repository_fingerprint(root)?)
    .then_some(report))
}

pub(in crate::rewrite) fn terminal_current(root: &Path, state: &RewriteState) -> bool {
    current(root, state)
        .ok()
        .flatten()
        .is_some_and(|r| r.status == ReviewStatus::Passed)
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    let terminal = state.phase == RewritePhase::SliceComplete
        && !state.api_inventory.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|a| a.status == RewriteApiStatus::Complete)
        && crate::rewrite::process_outputs::all_complete(state);
    let ready = worker::runtime::scopes(state)
        .iter()
        .any(|scope| worker::runtime::acceptance_ready(state, scope));
    if !terminal && !ready && state.source_review_rework.is_empty() {
        return Ok(None);
    }
    let report = current(root, state)?;
    if report
        .as_ref()
        .is_some_and(|r| r.status == ReviewStatus::Passed)
    {
        return Ok(None);
    }
    if report.as_ref().is_some_and(|r| rework_pending(state, r)) {
        return Ok(Some(rework_wait(root)));
    }
    if !terminal && !ready {
        return Ok(None);
    }
    // API quality execution owns the initial scan. A persisted failed/pending scan
    // and terminal delivery must expose an actionable review rather than a retry loop.
    if !terminal && report.is_none() {
        return Ok(None);
    }
    Ok(Some(review_action(root, report.as_ref())))
}

pub(in crate::rewrite) fn gate(
    root: &Path,
    state: &RewriteState,
    pr_base: &str,
) -> Result<Option<RewriteAction>> {
    if let Some(report) = current(root, state)? {
        if report.status == ReviewStatus::Passed {
            return Ok(None);
        }
        if rework_pending(state, &report) {
            return Ok(Some(rework_wait(root)));
        }
    }
    let report = check_locked(
        root,
        pr_base,
        state,
        RewriteReviewOptions {
            target_root: root.to_path_buf(),
            worktree: None,
            scope: None,
            evidence: None,
        },
    )?;
    Ok((report.status != ReviewStatus::Passed).then(|| {
        if rework_pending(state, &report) {
            rework_wait(root)
        } else {
            review_action(root, Some(&report))
        }
    }))
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
        summary: "source findings are assigned to a worker; continue worker events and integration, then rerun integrated review after the corrected handoff".into(),
        resource: "source_review_rework".into(),
        requested_api: None, blocking_api: None, active_operation: None,
        retry_after_seconds: 30,
        status: action::status_command_for_api(root, None),
    }
}

fn review_action(root: &Path, report: Option<&RewriteReviewReport>) -> RewriteAction {
    RewriteAction::SourceReviewRequired {
        summary: match report.map(|r| r.status) {
            Some(ReviewStatus::ChangesRequired) => "source review found code changes required; inspect review show and route each finding with review rework to its owning work item",
            Some(ReviewStatus::EvidenceRequired) => "inspect review show; investigate each spawn and rerun review check --evidence with startup/request ownership evidence",
            _ => "run integrated source review before final delivery",
        }.into(),
        check: action::command(root, vec!["review".into(), "check".into()], Vec::new()),
        show: action::command(root, vec!["review".into(), "show".into()], Vec::new()),
        rework: action::command(root, vec!["review".into(), "rework".into()], vec!["BACKEND_REWRITE_REVIEW_FINDING".into(), "BACKEND_REWRITE_REVIEW_OWNER".into()]),
    }
}
