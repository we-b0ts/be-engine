use super::*;
use crate::quality::QualityReportMethods;

/// Build an old source-review receipt for compatibility tests. Ordinary public
/// check now returns identity only; final inspection primitives remain covered.
pub(crate) fn inspect(options: RewriteReviewOptions) -> Result<RewriteReviewReport> {
    let mut report = crate::review::check(options.clone())?;
    if report.integration.is_some() && options.scope.is_none() {
        report.report_path = if report.worktree == fs::canonicalize(&options.target_root)? {
            integrated_path(&report.worktree)
        } else {
            crate::internal_runtime::root(&report.worktree).join("integration-review.json")
        };
    }
    let root = &report.worktree;
    let base = &report.validation.as_ref().unwrap().scan_base_revision;
    let (files, findings) = scan::scan(root, base)?;
    let mut evidence = options
        .evidence
        .as_deref()
        .map(read_json::<ReviewEvidence>)
        .transpose()?
        .unwrap_or_default();
    let state = RewriteStore::new(&options.target_root)?.load()?.unwrap();
    integrated::reuse_evidence(&options.target_root, root, &state, &findings, &mut evidence)?;
    let (mut status, evidence_files) = evidence::evaluate(root, &findings, &evidence)?;
    let quality = if status == ReviewStatus::Passed {
        let quality = if report.integration.is_some() {
            crate::quality::run(root, base)?
        } else {
            crate::quality::run_worker(root, base)?
        };
        let scope = if report.integration.is_some() {
            crate::quality::QualityScope::Integration
        } else {
            crate::quality::QualityScope::Worker
        };
        if !quality.passed_for(scope) {
            status = ReviewStatus::ChangesRequired;
        }
        Some(quality)
    } else {
        None
    };
    report.files = files;
    report.findings = findings;
    report.evidence = evidence;
    report.evidence_files = evidence_files;
    report.status = status;
    report.quality = quality;
    report.required_gates = crate::quality::gate_names();
    report.next_step.push_str(
        " Historical inspection covers the whole PR; base_revision is the delivery base.",
    );
    write_json(&report.report_path, &report)?;
    Ok(report)
}
