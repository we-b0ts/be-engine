//! Source review shared by local worker handoffs and integrated acceptance.
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::RewriteWorkScope;
use super::model::{RewriteAction, RewriteState};
use super::store::RewriteStore;
use super::{action, fingerprint, source_diff, worker};

mod candidate;
mod evidence;
mod integrated;
mod model;
mod repair;
mod scan;
pub use candidate::accept;
pub(super) use candidate::accept_locked as accept_integration;
#[cfg(test)]
use integrated::terminal_current;
pub(super) use integrated::{
    admission_current, gate, is_rework_wait, required_action, requires_delivery_review,
};
pub use model::*;
pub use repair::{rework, rework_with_report};

pub fn check(options: RewriteReviewOptions) -> Result<RewriteReviewReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow is not initialized")?;
    check_candidate(&target_root, &project, &state, options)
}

// The only complete quality-check pipeline. Both worker and integrator invoke
// this explicitly in their delivery worktree; coordinator advancement never does.
fn check_candidate(
    target_root: &Path,
    project: &crate::e2e_run::ResolvedProjectConfig,
    state: &RewriteState,
    options: RewriteReviewOptions,
) -> Result<RewriteReviewReport> {
    let root = source_diff::project_root_in_worktree(
        target_root,
        options.worktree.as_deref().unwrap_or(target_root),
    )?;
    candidate::same_repository(target_root, &root)?;
    let integration_mode = options.integration || options.worktree.is_none();
    let canonical_head = candidate::head(target_root)?;
    let canonical_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let (base, dispatch, integration) = if integration_mode {
        let dispatch =
            candidate::handoff(state, options.scope.as_ref(), options.handoff_id.as_deref())?;
        source_diff::git_text(
            &root,
            &["merge-base", "--is-ancestor", &canonical_head, "HEAD"],
        )
        .context("integration candidate must descend from the current canonical base")?;
        (
            canonical_head.clone(),
            dispatch,
            Some(IntegrationReview {
                canonical_base_revision: canonical_head.clone(),
                canonical_base_fingerprint: canonical_fingerprint.clone(),
                handoff_id: options.handoff_id.clone(),
            }),
        )
    } else {
        ensure!(
            options.handoff_id.is_none(),
            "worker review does not accept an integration handoff id"
        );
        let scope = options
            .scope
            .as_ref()
            .context("worker review requires --api or --process-output")?;
        worker::ensure_scope_confirmed(state, scope, "worker review")?;
        let assignment = assignment(state, scope)?;
        ensure!(
            root == assignment.worktree,
            "review must run against the worktree registered by worker confirm --worktree"
        );
        source_diff::git_text(&root, &["merge-base", "--is-ancestor", &assignment.base_revision, "HEAD"])
            .context("worker worktree is behind its dispatch base; coordinator must refresh it before review")?;
        (
            assignment.base_revision.clone(),
            Some(worker::dispatch_view(state, scope.clone(), None).dispatch_id),
            None,
        )
    };
    let head = candidate::head(&root)?;
    let current = fingerprint::repository_fingerprint(&root)?;
    let validation = ReviewValidation {
        canonical_root: target_root.into(),
        recording_run_id: state.recording_run_id.clone(),
        code_fingerprint: fingerprint::code_fingerprint(&root)?,
        context_fingerprint: candidate::context(target_root, project)?,
        scan_base_revision: candidate::scan_base(&root, &project.pr_base)?,
    };
    // Scan the whole PR in both modes, including code inherited before dispatch.
    let (files, findings) = scan::scan(&root, &validation.scan_base_revision)?;
    let mut evidence = if let Some(path) = &options.evidence {
        read_json::<ReviewEvidence>(path)?
    } else {
        ReviewEvidence::default()
    };
    integrated::reuse_evidence(target_root, &root, state, &findings, &mut evidence)?;
    let (mut status, evidence_files) = evidence::evaluate(&root, &findings, &evidence)?;
    let quality = if status == ReviewStatus::Passed {
        let quality = crate::rewrite::quality::run(
            &root,
            &validation.scan_base_revision,
            &project.target_quality_gates,
            &options.hardcode_ai_verified,
        )?;
        if !quality.passed(&project.target_quality_gates) {
            status = ReviewStatus::ChangesRequired;
        }
        Some(quality)
    } else {
        None
    };
    ensure!(
        current == fingerprint::repository_fingerprint(&root)? && head == candidate::head(&root)?,
        "code changed during review; run review check again"
    );
    let (_, fresh_project) = crate::e2e_run::resolve_project(target_root)?;
    ensure!(
        validation.context_fingerprint == candidate::context(target_root, &fresh_project)?
            && validation.scan_base_revision
                == candidate::scan_base(&root, &fresh_project.pr_base)?,
        "review configuration or inputs changed during checks; rerun review check"
    );
    if integration_mode {
        ensure!(
            canonical_head == candidate::head(target_root)?
                && canonical_fingerprint == fingerprint::repository_fingerprint(target_root)?,
            "canonical base changed while preparing integration review; refresh the candidate"
        );
    }
    // A returned delivery path must retain its original dispatch even after
    // another review or resumed turn. The coordinator submits this exact file.
    let report_path = if options.scope.is_some() {
        crate::internal_runtime::root(&root)
            .join("review-reports")
            .join(format!("{}.json", uuid::Uuid::new_v4().simple()))
    } else if integration_mode {
        if root == target_root {
            integrated_path(&root)
        } else {
            crate::internal_runtime::root(&root).join("integration-review.json")
        }
    } else {
        unreachable!("worker review requires a scope")
    };
    let report = RewriteReviewReport {
        schema_version: 2, rules_version: RULE_VERSION.into(), workflow_id: state.workflow_id.clone(),
        dispatch_id: dispatch, scope: options.scope, worktree: root, base_revision: base,
        head_revision: head, target_fingerprint: current, status, files, findings, evidence, evidence_files,
        report_path: report_path.clone(), quality, validation: Some(validation), integration,
        hardcode_ai_verified: options.hardcode_ai_verified, accepted_target_fingerprint: None,
        required_gates: crate::rewrite::quality::gate_names(&project.target_quality_gates),
        next_step: match status {
            ReviewStatus::Passed if integration_mode => "Return the exact candidate and this report. The coordinator must publish head_revision to canonical HEAD before submitting this report through worker report --activity integrated --review-report, or review accept --report for an unscoped review. If both HEADs already match, no merge or new commit is needed; equal file content alone is insufficient. Publication or verification is not performed by review check.",
            ReviewStatus::Passed => "Deliver this exact code and complete quality report; the coordinator must inspect source evidence before reporting handoff_ready with --review-report.",
            ReviewStatus::ChangesRequired => "Fix the reported source or quality findings in the delivery worktree. Inspect quality command log_path for compiler/test errors; for hardcoded domains follow the exact source-evidence contract and --hardcode-ai-verified. Rerun review check before returning a handoff.",
            ReviewStatus::EvidenceRequired => "Trace each spawn's startup entry and callers; supply --evidence with source locations and ownership, then rerun review check. Unknown/request ownership cannot pass.",
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
    let worktree = source_diff::project_root_in_worktree(root, worktree)?;
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
    root: &Path,
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
    ensure!(
        report.integration.is_none(),
        "worker handoff requires a worker review, not an integration candidate"
    );
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    candidate::validate(root, &assignment.worktree, state, &report, &project)?;
    Ok(report)
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

#[cfg(test)]
mod delivery_tests;
