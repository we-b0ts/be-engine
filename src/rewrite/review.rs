//! Source review shared by local worker handoffs and integrated acceptance.
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::RewriteWorkScope;
use super::model::{RewriteAction, RewriteState};
use super::store::RewriteStore;
use super::{action, fingerprint, source_diff, worker};

mod evidence;
mod integrated;
mod model;
mod repair;
mod scan;
pub(super) use integrated::{gate, is_rework_wait, required_action, terminal_current};
pub use model::*;
pub use repair::rework;

pub fn check(options: RewriteReviewOptions) -> Result<RewriteReviewReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    // Local workers never acquire the coordinator lock or write workflow state.
    let _lock = if options.worktree.is_none() {
        Some(store.lock()?)
    } else {
        None
    };
    if options.worktree.is_none() {
        ensure!(
            matches!(
                super::traffic_operation::state(&target_root)?,
                super::traffic_operation::TrafficOperationState::Absent
            ),
            "integrated review must wait for traffic verification"
        );
    }
    let state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    check_locked(&target_root, &project.pr_base, &state, options)
}

pub(super) fn check_locked(
    target_root: &Path,
    pr_base: &str,
    state: &RewriteState,
    options: RewriteReviewOptions,
) -> Result<RewriteReviewReport> {
    let (root, base, dispatch) = if let Some(worktree) = &options.worktree {
        let scope = options
            .scope
            .as_ref()
            .context("worker review requires --api or --process-output")?;
        worker::ensure_scope_confirmed(state, scope, "worker review")?;
        let assignment = assignment(state, scope)?;
        let root = fs::canonicalize(worktree)?;
        ensure!(
            root == assignment.worktree,
            "review must run against the worktree registered by worker confirm --worktree"
        );
        source_diff::git_text(&root, &["merge-base", "--is-ancestor", &assignment.base_revision, "HEAD"])
            .context("worker worktree is behind its dispatch base; coordinator must refresh it before review")?;
        (
            root,
            assignment.base_revision.clone(),
            Some(worker::dispatch_view(state, scope.clone(), None).dispatch_id),
        )
    } else {
        ensure!(
            options.scope.is_none(),
            "integrated review does not select a worker scope"
        );
        let base_ref = source_diff::resolve_pr_base(target_root, pr_base)?;
        let base = source_diff::git_text(target_root, &["merge-base", "HEAD", &base_ref])?
            .trim()
            .to_string();
        (target_root.to_path_buf(), base, None)
    };
    let current = fingerprint::repository_fingerprint(&root)?;
    let (files, findings) = scan::scan(&root, &base)?;
    let mut evidence = if let Some(path) = &options.evidence {
        read_json::<ReviewEvidence>(path)?
    } else {
        ReviewEvidence::default()
    };
    if dispatch.is_none() {
        integrated::reuse_evidence(&root, state, &findings, &mut evidence)?;
    }
    let (status, evidence_files) = evidence::evaluate(&root, &findings, &evidence)?;
    ensure!(
        current == fingerprint::repository_fingerprint(&root)?,
        "code changed during review; run review check again"
    );
    let report_path = if dispatch.is_some() {
        worker_report_path(&root)
    } else {
        integrated_path(&root)
    };
    let report = RewriteReviewReport {
        schema_version: 1, rules_version: RULE_VERSION.into(), workflow_id: state.workflow_id.clone(),
        dispatch_id: dispatch, scope: options.scope, worktree: root.clone(), base_revision: base,
        head_revision: source_diff::git_text(&root, &["rev-parse", "HEAD"])?.trim().into(),
        target_fingerprint: current, status, files, findings, evidence, evidence_files, report_path: report_path.clone(),
        next_step: match status {
            ReviewStatus::Passed => "Deliver this exact code and review report; the coordinator must inspect spawn evidence before reporting handoff_ready with --review-report. Integrated review: return to backend-rewrite status.",
            ReviewStatus::ChangesRequired => "Fix file-size/Value violations or request-owned spawn, then rerun review check. For an integrated finding, use review rework --finding <id> --owner 'api:METHOD /path' or --owner 'process-output:ID' to route it to its owning worker.",
            ReviewStatus::EvidenceRequired => "Trace each spawn to its startup entry and all callers. Supply a JSON {spawns:[{finding_id,ownership,startup_entry:{file,line,fact},call_chain:[{file,line,fact}],request_path_review,task_lifecycle}]} through review check --evidence. ownership is startup, request, or unknown. A callback registered at startup may still execute per request.",
        }.into(),
    };
    write_json(&report_path, &report)?;
    Ok(report)
}

pub fn show(target_root: PathBuf) -> Result<RewriteReviewReport> {
    let root = fs::canonicalize(target_root)?;
    let state = RewriteStore::new(&root)?
        .load()?
        .context("rewrite workflow is absent")?;
    integrated::current(&root, &state)?
        .context("integrated review is absent or stale; run review check again")
}

pub(super) fn context(
    root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> ReviewContext {
    let assignment = state
        .worker_bindings
        .get(&scope.binding_key())
        .and_then(|b| b.review_assignment.clone());
    let mut argv = vec![
        "review".into(),
        "check".into(),
        "--worktree".into(),
        assignment
            .as_ref()
            .map(|a| a.worktree.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<assigned-worktree>".into()),
    ];
    match scope {
        RewriteWorkScope::Api { api } => argv.extend(["--api".into(), api.clone()]),
        RewriteWorkScope::ProcessOutput { id } => {
            argv.extend(["--process-output".into(), id.clone()])
        }
    }
    ReviewContext {
        assignment,
        rework: state
            .source_review_rework
            .get(&scope.binding_key())
            .cloned(),
        check: action::command(root, argv, Vec::new()),
        integrated_findings: action::command(
            root,
            vec!["review".into(), "show".into()],
            Vec::new(),
        ),
    }
}

pub(super) fn bind(
    root: &Path,
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    worktree: Option<&Path>,
    new_dispatch: bool,
) -> Result<bool> {
    let binding = state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .context("worker binding is absent")?;
    let Some(worktree) = worktree.or_else(|| {
        binding
            .review_assignment
            .as_ref()
            .map(|a| a.worktree.as_path())
    }) else {
        return Ok(false);
    };
    let worktree = fs::canonicalize(worktree)?;
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
        common(root)? == common(&worktree)?,
        "worker worktree belongs to a different Git repository"
    );
    if new_dispatch || binding.review_assignment.is_none() {
        binding.review_assignment = Some(ReviewAssignment {
            worktree,
            base_revision: source_diff::git_text(root, &["rev-parse", "HEAD"])?
                .trim()
                .into(),
        });
        binding.review_report = None;
        return Ok(true);
    }
    ensure!(
        binding
            .review_assignment
            .as_ref()
            .is_some_and(|a| a.worktree == worktree),
        "cannot replace a worktree within a confirmed dispatch"
    );
    Ok(false)
}

fn assignment<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Result<&'a ReviewAssignment> {
    state.worker_bindings.get(&scope.binding_key()).and_then(|b| b.review_assignment.as_ref())
        .context("review assignment is missing; coordinator must repeat worker confirm for the current dispatch with --worktree")
}

pub(super) fn accept_handoff(
    state: &RewriteState,
    scope: &RewriteWorkScope,
    path: Option<&Path>,
) -> Result<RewriteReviewReport> {
    let path = path.context("handoff_ready requires --review-report from worker review check; resume an ended worker as idle if its delivery is incomplete")?;
    let report: RewriteReviewReport = read_json(path)?;
    let assignment = assignment(state, scope)?;
    let dispatch = worker::dispatch_view(state, scope.clone(), None).dispatch_id;
    ensure!(
        report.workflow_id == state.workflow_id
            && report.dispatch_id.as_deref() == Some(dispatch.as_str())
            && report.scope.as_ref() == Some(scope),
        "review report belongs to another workflow or dispatch"
    );
    ensure!(
        report.worktree == assignment.worktree
            && report.base_revision == assignment.base_revision
            && report.rules_version == RULE_VERSION,
        "review assignment or rules changed; rerun review check"
    );
    ensure!(
        report.status == ReviewStatus::Passed
            && report.target_fingerprint
                == fingerprint::repository_fingerprint(&assignment.worktree)?,
        "handoff code changed or review did not pass; rerun review check"
    );
    ensure!(
        report.head_revision
            == source_diff::git_text(&assignment.worktree, &["rev-parse", "HEAD"])?.trim(),
        "commit changed after review; rerun review check for the delivered commit"
    );
    let (status, _) = evidence::evaluate(&assignment.worktree, &report.findings, &report.evidence)?;
    ensure!(
        status == ReviewStatus::Passed,
        "handoff spawn review is incomplete"
    );
    Ok(report)
}

fn worker_report_path(root: &Path) -> PathBuf {
    crate::internal_runtime::root(root).join("worker-review.json")
}
fn integrated_path(root: &Path) -> PathBuf {
    crate::internal_runtime::root(root).join("rewrite/source-review.json")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)
        .with_context(|| format!("cannot read review document {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid review document {}", path.display()))
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let parent = path.parent().context("review report has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".review-{}.tmp", uuid::Uuid::new_v4().simple()));
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(test)]
pub(in crate::rewrite) mod tests;
