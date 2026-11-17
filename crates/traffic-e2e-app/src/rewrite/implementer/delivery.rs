//! Freeze accepted delivery identity independently of the reusable worker checkout.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Result, ensure};

use crate::rewrite::{fingerprint, review::RewriteReviewReport, source_diff};

pub(super) fn freeze(
    root: &Path,
    handoff: &str,
    report: &RewriteReviewReport,
) -> Result<RewriteReviewReport> {
    let key = fingerprint::id(&[
        "implementer-delivery-v1",
        &report.workflow_id,
        report.dispatch_id.as_deref().unwrap_or_default(),
        handoff,
    ]);
    let key = key.trim_start_matches("fnv1a64:");
    let directory = crate::internal_runtime::root(root)
        .join("implementer-deliveries")
        .join(key);
    fs::create_dir_all(&directory)?;
    let path = directory.join("review.json");
    let reference = format!("refs/backend-rewrite/deliveries/{key}");
    let mut frozen = report.clone();
    frozen.report_path = path.clone();
    if path.is_file() {
        let previous: RewriteReviewReport = serde_json::from_slice(&fs::read(&path)?)?;
        ensure!(
            previous.workflow_id == frozen.workflow_id
                && previous.dispatch_id == frozen.dispatch_id
                && previous.head_revision == frozen.head_revision
                && previous.target_fingerprint == frozen.target_fingerprint,
            "handoff identity is already frozen for different code"
        );
        return Ok(previous);
    }
    // A durable ref keeps the commit reachable after the slot branch is reused.
    if let Ok(previous) = source_diff::git_text(root, &["rev-parse", "--verify", &reference]) {
        ensure!(
            previous.trim() == report.head_revision,
            "handoff ref already identifies different code"
        );
    } else {
        source_diff::git_text(root, &["update-ref", &reference, &report.head_revision, ""])?;
    }
    let temporary = directory.join(format!("review-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&frozen)?)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    Ok(frozen)
}
