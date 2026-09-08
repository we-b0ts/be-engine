use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::model::*;
use super::scan::file_hash;

pub(super) fn evaluate(
    root: &Path,
    findings: &[ReviewFinding],
    evidence: &ReviewEvidence,
) -> Result<(ReviewStatus, BTreeMap<PathBuf, String>)> {
    let mut seen = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut rejected = findings
        .iter()
        .any(|f| f.rule != ReviewRule::SpawnOwnership);
    let mut pending = false;
    for item in &evidence.spawns {
        ensure!(
            seen.insert(&item.finding_id),
            "duplicate spawn evidence {}",
            item.finding_id
        );
        let finding = findings
            .iter()
            .find(|f| f.id == item.finding_id && f.rule == ReviewRule::SpawnOwnership)
            .with_context(|| {
                format!(
                    "spawn evidence {} is stale or has no matching finding; rerun review check",
                    item.finding_id
                )
            })?;
        match item.ownership {
            SpawnOwnership::Request => rejected = true,
            SpawnOwnership::Unknown => pending = true,
            SpawnOwnership::Startup => {
                let entry = item
                    .startup_entry
                    .as_ref()
                    .context("startup ownership requires startup_entry code evidence")?;
                ensure!(
                    !item.call_chain.is_empty(),
                    "startup ownership requires a call_chain"
                );
                ensure!(
                    item.call_chain
                        .iter()
                        .any(|e| e.file == finding.file && e.line == finding.line),
                    "call_chain must include the reported spawn location"
                );
                ensure!(
                    !item.request_path_review.trim().is_empty(),
                    "request_path_review must explain caller inspection and actual trigger timing"
                );
                ensure!(
                    !item.task_lifecycle.trim().is_empty(),
                    "task_lifecycle must explain ownership, bounds, errors, cancellation and shutdown"
                );
                for location in std::iter::once(entry).chain(&item.call_chain) {
                    ensure!(
                        safe_path(&location.file)
                            && location.line > 0
                            && !location.fact.trim().is_empty(),
                        "invalid code evidence location or empty fact"
                    );
                    let source = std::fs::read_to_string(root.join(&location.file))?;
                    ensure!(
                        source.lines().nth(location.line - 1).is_some(),
                        "evidence line is absent: {}:{}",
                        location.file.display(),
                        location.line
                    );
                    files.insert(location.file.clone(), file_hash(root, &location.file)?);
                }
            }
        }
    }
    pending |= findings
        .iter()
        .any(|f| f.rule == ReviewRule::SpawnOwnership && !seen.contains(&f.id));
    Ok((
        if rejected {
            ReviewStatus::ChangesRequired
        } else if pending {
            ReviewStatus::EvidenceRequired
        } else {
            ReviewStatus::Passed
        },
        files,
    ))
}

pub(super) fn safe_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

pub(super) fn reusable(root: &Path, report: &RewriteReviewReport) -> bool {
    report.rules_version == RULE_VERSION
        && report.status == ReviewStatus::Passed
        && report
            .files
            .iter()
            .chain(&report.evidence_files)
            .all(|(file, hash)| file_hash(root, file).is_ok_and(|current| current == *hash))
}
