//! Admission of the final checked candidate and its subsequent complete sweep.
//! This owner never executes repository commands or treats first-pass evidence
//! as proof that the checked candidate has completed its final regression.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use crate::rewrite::model::{RewriteApiStatus, RewritePhase};
mod inputs;
pub(super) fn input_fingerprint(root: &Path) -> Result<String> {
    inputs::fingerprint(root)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::rewrite) struct AcceptedReview {
    pub report_path: PathBuf,
    pub context: String,
    pub receipt_identity: String,
    /// Progress of the sweep started by admission, independent of receipt age.
    pub remaining: BTreeSet<String>,
}

pub(in crate::rewrite) fn ready(state: &RewriteState) -> bool {
    state.phase != RewritePhase::RecordingRequired
        && !crate::rewrite::transition::replay_completion_pending(state)
        && !state.api_inventory.is_empty()
        && (state.api_inventory.iter().any(|item| {
            matches!(
                item.status,
                RewriteApiStatus::Complete | RewriteApiStatus::RevalidationPending
            ) || (item.status == RewriteApiStatus::Active
                && state.phase == RewritePhase::ApiPending)
        }) || state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Skipped))
        && state.source_review_rework.is_empty()
        && state.case_pattern_identification.is_none()
        && state.api_inventory.iter().all(|item| match item.status {
            RewriteApiStatus::Complete
            | RewriteApiStatus::Skipped
            | RewriteApiStatus::RevalidationPending
            | RewriteApiStatus::SystemRepairRequired => true,
            RewriteApiStatus::Active if item.api == state.api => {
                matches!(
                    state.phase,
                    RewritePhase::SliceComplete | RewritePhase::SystemRepairRequired
                ) || (state.phase == RewritePhase::ApiPending
                    && crate::rewrite::inventory::revalidation_round::contains(state, &item.api))
            }
            _ => false,
        })
}

/// Excludes changing attempt/status counters and public progress, but binds the
/// workflow, recording, selected routes, skip policy and all verification rules.
pub(super) fn context(root: &Path, state: &RewriteState) -> Result<String> {
    let mut inventory = state
        .api_inventory
        .iter()
        .map(|item| -> Result<_> {
            // A legacy inventory adopts its recorded canonical pattern on first
            // activation. Bind that effective route so adoption is not a scope edit.
            let source_route = match item
                .source_route
                .as_ref()
                .or_else(|| state.source_route_bindings.get(&item.api))
            {
                Some(route) => route.clone(),
                None => item
                    .api
                    .parse::<crate::RecordingApi>()?
                    .path_pattern()
                    .to_string(),
            };
            Ok((
                &item.api,
                source_route,
                item.status == RewriteApiStatus::Skipped,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    inventory.sort_by(|left, right| left.0.cmp(right.0));
    let policy = fingerprint::policy_file(root)?;
    let policy = match fs::read_to_string(policy) {
        Ok(policy) => policy,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("failed to read final regression policy"),
    };
    Ok(fingerprint::id(&[
        "pre-revalidation-context-v2",
        &crate::e2e_run::resolve_project(root)?.1.quality_check,
        &state.workflow_id,
        &state.recording_run_id,
        &serde_json::to_string(&inventory)?,
        &policy,
    ]))
}

pub(super) fn ensure_committed(root: &Path) -> Result<()> {
    inputs::ensure_committed(root)?;
    ensure!(
        fingerprint::matches_revision(root, "HEAD")?,
        "commit the final candidate's target and managed code before review check --pre-revalidation or final admission"
    );
    Ok(())
}

fn receipt_identity(report: &RewriteReviewReport) -> Result<String> {
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(report)?)))
}

fn checked_path(root: &Path) -> PathBuf {
    crate::internal_runtime::root(root).join("rewrite/pre-revalidation-candidate.json")
}

pub(super) fn remember(root: &Path, report: &mut RewriteReviewReport) -> Result<()> {
    if report.status == ReviewStatus::Passed {
        report.report_path = crate::internal_runtime::root(root)
            .join("rewrite/pre-revalidation-candidates")
            .join(format!("{}.json", uuid::Uuid::new_v4().simple()));
        write_json(&report.report_path, report)?;
        write_json(&checked_path(root), report)?;
    }
    Ok(())
}

/// Repeated commands and lost responses reuse a passing exact candidate. This
/// only reads/revalidates receipts; it never advances or resets the sweep.
pub(super) fn reusable(
    root: &Path,
    worktree: &Path,
    state: &RewriteState,
    project: &crate::e2e_run::ResolvedProjectConfig,
) -> Result<Option<RewriteReviewReport>> {
    let worktree = source_diff::project_root_in_worktree(root, worktree)?;
    candidate::same_repository(root, &worktree)?;
    ensure_committed(&worktree)?;
    let path = if current(root, state) {
        accepted_path(root)
    } else {
        checked_path(root)
    };
    let Ok(report) = read_json::<RewriteReviewReport>(&path) else {
        return Ok(None);
    };
    if report.pre_revalidation.is_none()
        || report.status != ReviewStatus::Passed
        || candidate::fresh(root, &worktree, state, &report, project).is_err()
        || candidate::checks_passed(&worktree, &report, project).is_err()
    {
        return Ok(None);
    }
    let published = candidate::head(root)?;
    if current(root, state) {
        source_diff::git_text(
            &worktree,
            &["merge-base", "--is-ancestor", &report.head_revision, "HEAD"],
        )?;
        restore_report(root, &report)?;
        return Ok(Some(report));
    }
    if candidate::head(&worktree)? == report.head_revision
        && report.integration.as_ref().is_some_and(|integration| {
            published == integration.canonical_base_revision || published == report.head_revision
        })
    {
        restore_report(root, &report)?;
        return Ok(Some(report));
    }
    Ok(None)
}

fn restore_report(root: &Path, report: &RewriteReviewReport) -> Result<()> {
    // Canonical cached reports survive integration worktree cleanup. Restore
    // only engine-owned candidate artifacts, never a path supplied externally.
    let directory = crate::internal_runtime::root(root).join("rewrite/pre-revalidation-candidates");
    ensure!(
        report.report_path.parent() == Some(directory.as_path()),
        "cached final report is outside the canonical candidate artifact directory"
    );
    write_json(&report.report_path, report)
}

fn accepted_path(root: &Path) -> PathBuf {
    crate::internal_runtime::root(root).join("rewrite/pre-revalidation-review.json")
}

pub(in crate::rewrite) fn current(root: &Path, state: &RewriteState) -> bool {
    let Some(accepted) = &state.pre_revalidation_review else {
        return false;
    };
    let validate = || -> Result<()> {
        ensure!(
            accepted.report_path == accepted_path(root),
            "final receipt path changed"
        );
        ensure!(
            accepted.context == context(root, state)?,
            "final scope changed"
        );
        let report: RewriteReviewReport = read_json(&accepted.report_path)?;
        ensure!(
            accepted.receipt_identity == receipt_identity(&report)?,
            "final receipt was replaced before workflow admission committed"
        );
        ensure!(
            report.pre_revalidation.as_deref() == Some(accepted.context.as_str()),
            "final receipt binding changed"
        );
        let (_, project) = crate::e2e_run::resolve_project(root)?;
        candidate::validate_accepted(root, state, &report, &project)
    };
    validate().is_ok()
}

pub(in crate::rewrite) fn completion_current(root: &Path, state: &RewriteState) -> bool {
    current(root, state)
        && state
            .pre_revalidation_review
            .as_ref()
            .is_some_and(|review| review.remaining.is_empty())
}

pub(in crate::rewrite) fn required_action(
    root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    if current(root, state) {
        return Ok(None);
    }
    if !ready(state) {
        if state.phase == RewritePhase::ApiPending
            && crate::rewrite::inventory::revalidation_round::contains(state, &state.api)
        {
            return Ok(Some(RewriteAction::WaitRequired {
                summary: "The final candidate changed while repairs remain. Suspend the old sweep with next, finish the responsible API repairs, then refresh the final check before resuming full revalidation.".into(),
                execution_mode: None, resource: "pre_revalidation_candidate".into(),
                requested_api: None, blocking_api: None, active_operation: None,
                retry_after_seconds: 5, status: action::status_command(root),
            }));
        }
        return Ok(None);
    }
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    Ok(Some(RewriteAction::PreRevalidationReviewRequired {
        quality_check: project.quality_check.clone(),
        quality_paths: std::iter::once(PathBuf::from(".")).chain(project.managed_paths).collect(),
        summary: "Before the final full revalidation sweep, the code integrator must run quality_check on the final committed candidate across quality_paths in its retained integration worktree. After success, execute commands.check to report the successful tool; review check performs source/isolation checks and never executes repository quality commands. Fix routine findings there, publish the exact passing candidate, then admit its report through commands.accept. Ordinary worker/integration receipts cannot satisfy this existing stage.".into(),
        check: action::command(root, vec!["review".into(), "check".into(), "--pre-revalidation".into(), "--quality-check".into(), project.quality_check], vec!["BACKEND_REWRITE_REVIEW_WORKTREE".into()]),
        accept: action::command(root, vec!["review".into(), "accept".into()], vec!["BACKEND_REWRITE_REVIEW_REPORT".into()]),
    }))
}

/// Retire an invalid frozen sweep before worker scheduling. Keep every pending
/// obligation; a fresh final admission will restart the entire selected sweep.
pub(in crate::rewrite) fn reconcile(root: &Path, state: &mut RewriteState) -> Result<bool> {
    if state.revalidation_round.is_none()
        || current(root, state)
        || ready(state)
        || crate::rewrite::transition::replay_completion_pending(state)
    {
        return Ok(false);
    }
    if state.phase == RewritePhase::ApiPending
        && crate::rewrite::inventory::revalidation_round::contains(state, &state.api)
    {
        if let Some(index) = state.current_api_index {
            state.api_inventory[index].status = RewriteApiStatus::RevalidationPending;
        }
        state.current_api_index = None;
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = false;
    }
    state.revalidation_round = None;
    state.bump();
    Ok(true)
}

/// Called only after full receipt validation and exact candidate publication.
/// Keep a separate accepted artifact so later ordinary integration receipts
/// cannot overwrite the final check. Repeated admission cannot reset the sweep.
pub(super) fn admit(
    root: &Path,
    state: &mut RewriteState,
    report: &RewriteReviewReport,
) -> Result<()> {
    ensure!(
        ready(state),
        "final review requires completed implementation acceptances"
    );
    if current(root, state) {
        return Ok(());
    }
    let context = context(root, state)?;
    ensure!(
        report.pre_revalidation.as_deref() == Some(context.as_str()),
        "final review scope is stale"
    );
    let path = accepted_path(root);
    let case_source = state.case_source.clone();
    let source_revision = state.source_revision.clone();
    let receipt_identity = receipt_identity(report)?;
    write_json(&path, report)?;
    if state.phase == RewritePhase::SystemRepairRequired
        && let Some(index) = state.current_api_index
    {
        state.api_inventory[index].status = RewriteApiStatus::SystemRepairRequired;
        state
            .parked_slices
            .insert(state.api.clone(), state.active_slice.clone());
    }
    let mut remaining = BTreeSet::new();
    for item in &mut state.api_inventory {
        if matches!(
            item.status,
            RewriteApiStatus::Complete
                | RewriteApiStatus::RevalidationPending
                | RewriteApiStatus::Active
        ) {
            remaining.insert(item.api.clone());
            item.status = RewriteApiStatus::RevalidationPending;
            item.e2e_current = false;
            state.parked_slices.remove(&item.api);
        }
    }
    state.pre_revalidation_review = Some(AcceptedReview {
        report_path: path,
        context,
        receipt_identity,
        remaining,
    });
    state.revalidation_round = None;
    if let Some(index) = state
        .api_inventory
        .iter()
        .position(|item| item.status == RewriteApiStatus::RevalidationPending)
    {
        crate::rewrite::inventory::resume_at(state, index)?;
    }
    state.case_source = case_source;
    state.source_revision = source_revision;
    state.bump();
    Ok(())
}

#[cfg(test)]
mod tests;
