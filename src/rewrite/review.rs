//! Source review shared by local worker handoffs and integrated acceptance.
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::RewriteWorkScope;
use super::model::{RewriteAction, RewriteState};
use super::store::RewriteStore;
use super::{action, fingerprint, source_diff, worker};

mod batch;
mod candidate;
mod evidence;
mod integrated;
mod model;
pub(in crate::rewrite) mod pre_revalidation;
mod repair;
mod scan;
pub use batch::{
    RewriteIntegrationBatchDelivery, RewriteIntegrationBatchOptions, RewriteIntegrationBatchReport,
    check_file as check_batch_file, export as export_batch,
};
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
    ensure!(
        options.quality_check.is_none(),
        "--quality-check requires --pre-revalidation"
    );
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow is not initialized")?;
    check_candidate(&target_root, &project, &state, options, None, false)
}

pub fn check_batch(
    options: RewriteReviewOptions,
    handoffs: Vec<IntegrationHandoffSelection>,
) -> Result<RewriteReviewReport> {
    ensure!(
        options.integration
            && options.quality_check.is_none()
            && options.worktree.is_some()
            && options.scope.is_none()
            && options.handoff_id.is_none(),
        "batch review requires --integration without a single work-item selector"
    );
    ensure!(
        !handoffs.is_empty(),
        "batch review requires at least one handoff"
    );
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow is not initialized")?;
    check_candidate(
        &target_root,
        &project,
        &state,
        options,
        Some(&handoffs),
        false,
    )
}

/// The existing final-stage entry point binds the integrator's successful
/// quality-check attestation to the frozen candidate without executing the tool.
pub fn check_pre_revalidation(mut options: RewriteReviewOptions) -> Result<RewriteReviewReport> {
    ensure!(
        options.scope.is_none() && options.handoff_id.is_none() && options.worktree.is_some(),
        "pre-revalidation review requires a global integration worktree without a handoff"
    );
    options.integration = true;
    let (root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    ensure!(
        options.quality_check.as_deref() == Some(project.quality_check.as_str()),
        "run delivery.quality_check ({}) on the final committed candidate, then report success using --quality-check {}",
        project.quality_check,
        project.quality_check
    );
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    ensure!(
        matches!(
            super::traffic_operation::state(&root)?,
            super::traffic_operation::TrafficOperationState::Absent
        ),
        "final review must wait for traffic verification"
    );
    let state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    ensure!(
        pre_revalidation::ready(&state),
        "finish API implementations and integrations before final review"
    );
    if let Some(report) = pre_revalidation::reusable(
        &root,
        options.worktree.as_deref().expect("worktree checked above"),
        &state,
        &project,
    )? {
        return Ok(report);
    }
    let mut report = check_candidate(&root, &project, &state, options, None, true)?;
    pre_revalidation::remember(&root, &mut report)?;
    Ok(report)
}

// Every review executes engine source/isolation checks only. Final mode also
// binds the agent-owned quality check to the complete regression scope.
fn check_candidate(
    target_root: &Path,
    project: &crate::e2e_run::ResolvedProjectConfig,
    state: &RewriteState,
    mut options: RewriteReviewOptions,
    batch: Option<&[IntegrationHandoffSelection]>,
    final_review: bool,
) -> Result<RewriteReviewReport> {
    options.scope = options
        .scope
        .as_ref()
        .map(|scope| super::api_selector::canonical_scope(state, scope));
    let root = source_diff::project_root_in_worktree(
        target_root,
        options.worktree.as_deref().unwrap_or(target_root),
    )?;
    candidate::same_repository(target_root, &root)?;
    let (_, candidate_project) = crate::e2e_run::resolve_project(&root)?;
    ensure!(
        candidate_project.managed_paths == project.managed_paths,
        "delivery.managed_paths differs from the canonical target; publish configuration changes before reviewing code"
    );
    if final_review {
        ensure!(
            candidate_project.quality_check == project.quality_check,
            "delivery.quality_check differs from the canonical target; publish configuration changes before final review"
        );
        pre_revalidation::ensure_committed(&root)?;
    }
    let integration_mode = options.integration || options.worktree.is_none();
    let final_context = final_review
        .then(|| pre_revalidation::context(target_root, state))
        .transpose()?;
    let quality_scope = if final_review {
        super::quality::QualityScope::PreRevalidation
    } else if integration_mode {
        super::quality::QualityScope::Integration
    } else {
        super::quality::QualityScope::Worker
    };
    let canonical_head = candidate::head(target_root)?;
    let canonical_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let (base, dispatch, integration) = if integration_mode {
        let (dispatch, handoffs) = if let Some(batch) = batch {
            (None, candidate::batch_handoffs(state, batch)?)
        } else {
            (
                candidate::handoff(state, options.scope.as_ref(), options.handoff_id.as_deref())?,
                Vec::new(),
            )
        };
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
                handoffs,
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
            .context("worker review requires --api")?;
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
        final_inputs_fingerprint: final_review
            .then(|| pre_revalidation::input_fingerprint(&root))
            .transpose()?,
    };
    source_diff::ensure_changed_paths_managed(&root, &validation.scan_base_revision)?;
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
        let quality = if final_review {
            super::quality::run_pre_revalidation(
                &root,
                &validation.scan_base_revision,
                &project.quality_check,
                &options.hardcode_ai_verified,
            )?
        } else if integration_mode {
            super::quality::run(
                &root,
                &validation.scan_base_revision,
                &options.hardcode_ai_verified,
            )?
        } else {
            super::quality::run_worker(
                &root,
                &validation.scan_base_revision,
                &options.hardcode_ai_verified,
            )?
        };
        let passed = if quality_scope == super::quality::QualityScope::Integration {
            quality.passed()
        } else {
            quality.passed_for(quality_scope)
        };
        if !passed {
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
    if let Some(context) = final_context.as_ref() {
        ensure!(
            validation.final_inputs_fingerprint.as_ref()
                == Some(&pre_revalidation::input_fingerprint(&root)?),
            "Cargo or toolchain inputs changed during final review; rerun final review"
        );
        let fresh_state = RewriteStore::new(target_root)?
            .load()?
            .context("workflow disappeared during final review")?;
        ensure!(
            pre_revalidation::ready(&fresh_state)
                && context == &pre_revalidation::context(target_root, &fresh_state)?,
            "final regression scope or policy changed during review; rerun final review"
        );
    }
    // A returned delivery path must retain its original dispatch even after
    // another review or resumed turn. The coordinator submits this exact file.
    let report_path = if final_review || options.scope.is_some() || batch.is_some() {
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
    let required_gates = if final_review {
        super::quality::final_gate_names()
    } else {
        super::quality::gate_names()
    };
    let inherited_scope = validation.scan_base_revision != base;
    let mut report = RewriteReviewReport {
        schema_version: if batch.is_some() { 3 } else { 2 },
        rules_version: RULE_VERSION.into(), workflow_id: state.workflow_id.clone(),
        dispatch_id: dispatch, scope: options.scope, worktree: root, base_revision: base,
        head_revision: head, target_fingerprint: current, status, files, findings, evidence, evidence_files,
        report_path: report_path.clone(), quality, validation: Some(validation), integration, pre_revalidation: final_context,
        hardcode_ai_verified: options.hardcode_ai_verified, accepted_target_fingerprint: None,
        required_gates,
        next_step: match status {
            ReviewStatus::Passed if final_review => "Publish this exact checked candidate, then use review accept --report to admit its final receipt and start the full revalidation sweep. The reported quality_check was executed by the integrator; review check does not execute repository commands. Progress-only publication preserves the receipt; code, inputs, policy or scope changes require a fresh final check.",
            ReviewStatus::ChangesRequired if final_review => "Inspect the source/isolation findings. The integrator fixes routine findings, commits corrections, reruns the configured quality_check after relevant changes and reports success through review check --pre-revalidation --quality-check TOOL. Return API behavior decisions to the responsible worker. Full revalidation starts only after the passing exact candidate is published and admitted.",
            ReviewStatus::Passed if batch.is_some() => "Return the exact candidate, this engine source/isolation report, and any targeted tests performed. This ordinary review does not run fmt, tests or Clippy. The coordinator must publish head_revision, then use this report for listed handoffs still handoff_ready. Retain already integrated handoffs and resume only unreported handoffs after interruption; review check does not publish or verify APIs.",
            ReviewStatus::Passed if integration_mode => "Return this exact candidate, the engine source/isolation report, and any targeted tests performed. This ordinary review does not run fmt, tests or Clippy. The coordinator must publish head_revision before worker report --activity integrated --review-report or review accept --report. Matching HEADs need no new commit; equal files alone do not prove publication. Formal API acceptance remains separate.",
            ReviewStatus::Passed => "Deliver this exact code and worker source/isolation report, with the relevant tests you ran. The code integrator runs the configured quality_check and reports success at final pre-revalidation review before the full sweep. The coordinator must inspect source evidence before handoff_ready; integration requires its own candidate review.",
            ReviewStatus::ChangesRequired if integration_mode => "Fix the reported source/isolation findings in the assigned integration worktree. The integrator owns routine formatting/Clippy repairs; the integrator executes the configured quality_check before reporting final pre-revalidation review. Return API behavior decisions to the responsible worker. Follow the exact hardcode source-evidence contract when applicable, commit corrections and rerun candidate review.",
            ReviewStatus::ChangesRequired => "Fix the reported source or Replay-isolation findings in the assigned worker worktree, then rerun worker review. For hardcoded domains follow the exact source-evidence contract and --hardcode-ai-verified. Run relevant tests as needed; the integrator runs the configured final quality_check before full revalidation.",
            ReviewStatus::EvidenceRequired => "Trace each spawn's startup entry and callers; supply --evidence with source locations and ownership, then rerun review check. Unknown/request ownership cannot pass.",
        }.into(),
    };
    if inherited_scope && report.status != ReviewStatus::Passed {
        report.next_step.push_str(" Review covers the whole PR from validation.scan_base_revision, including code inherited before dispatch; base_revision is the delivery base. Keep that scope. Supply truthful current evidence for inherited findings; valid integrated evidence is reused automatically. A finding in another API's inherited code does not by itself require rewriting that code.");
    }
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
