//! Candidate identity and quality-receipt validation.
use crate::quality::QualityReportMethods;
use crate::{evidence, fingerprint, model::*, source_diff};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};
use traffic_engine::e2e_run::ResolvedProjectConfig;
use traffic_rewrite_model::rewrite::model::RewriteState;

pub fn same_repository(root: &Path, worktree: &Path) -> Result<()> {
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

pub fn head(root: &Path) -> Result<String> {
    Ok(source_diff::git_text(root, &["rev-parse", "HEAD"])?
        .trim()
        .into())
}

pub fn scan_base(root: &Path, pr_base: &str) -> Result<String> {
    let base = source_diff::resolve_pr_base(root, pr_base)?;
    Ok(source_diff::git_text(root, &["merge-base", "HEAD", &base])?
        .trim()
        .into())
}

pub fn context(root: &Path, project: &ResolvedProjectConfig) -> Result<String> {
    Ok(fingerprint::id(&[
        "review-validation-context-v1",
        &crate::quality::policy_fingerprint()?,
        &project.pr_base,
        &serde_json::to_string(&project.managed_paths)?,
        &traffic_engine::startup::startup_snapshot_revision(root)?,
        &traffic_engine::startup::startup_environment_revision(root)?,
    ]))
}

pub fn fresh(
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
                == Some(&crate::final_inputs::fingerprint(code_root)?),
            "Cargo or toolchain inputs changed after final review; rerun review check --pre-revalidation"
        );
        ensure!(
            binding == &crate::final_inputs::context(root, state)?,
            "final review scope, recording or policy changed; rerun review check --pre-revalidation"
        );
    }
    Ok(())
}

pub fn validate(
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

pub fn validate_accepted(
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
    checks_passed(root, report, project)
}

pub fn checks_passed(
    code_root: &Path,
    report: &RewriteReviewReport,
    project: &ResolvedProjectConfig,
) -> Result<()> {
    ensure!(
        report.status == ReviewStatus::Passed,
        "review did not pass; fix the delivery and rerun review check"
    );
    // Delivery receipts bind a frozen commit and dispatch, not source quality.
    // They cannot satisfy the independently bound final-review gate.
    if report.pre_revalidation.is_none() && report.required_gates == ["delivery-identity"] {
        ensure!(
            report.quality.is_none()
                && report.findings.is_empty()
                && report.files.is_empty()
                && report.evidence.spawns.is_empty()
                && report.evidence_files.is_empty(),
            "identity-only delivery cannot contain source-review results"
        );
        return Ok(());
    }
    let quality = report
        .quality
        .as_ref()
        .context("review lacks mandatory quality checks")?;
    if report.pre_revalidation.is_some() {
        crate::final_inputs::ensure_candidate_committed(code_root)?;
        ensure!(report.integration.is_some() && report.scope.is_none()
            && report.integration.as_ref().is_some_and(|review| review.handoff_id.is_none() && review.handoffs.is_empty()),
            "final review must cover the global integration candidate");
        quality.ensure_pre_revalidation(&project.quality_check)?;
    } else if report.integration.is_some() {
        quality.ensure_passed()?;
    } else {
        quality.ensure_passed_for(crate::quality::QualityScope::Worker)?;
    }
    let (status, _) = evidence::evaluate(code_root, &report.findings, &report.evidence)?;
    ensure!(
        status == ReviewStatus::Passed,
        "review source evidence is incomplete"
    );
    Ok(())
}
