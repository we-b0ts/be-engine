//! Shared legacy review fixture for coordinator unit tests.
pub(crate) use super::legacy_receipt::inspect as legacy_source_review;
use super::*;
use legacy_source_review as check;

pub(crate) fn worker_report(root: &Path, scope: RewriteWorkScope) -> PathBuf {
    check(RewriteReviewOptions {
        target_root: root.into(),
        worktree: Some(root.into()),
        scope: Some(scope),
        evidence: None,
        integration: false,
        quality_check: None,
        handoff_id: None,
    })
    .map(|report| report.report_path)
    .unwrap_or_else(|_| root.join("missing-review.json"))
}
