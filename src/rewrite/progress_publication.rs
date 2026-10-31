use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::model::{RewriteApiStatus, RewritePhase, RewriteState};
use crate::verification_progress::{self, VerificationStage};

const PUBLIC_PROGRESS: &str = ".traffic-e2e/progress.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PublicationState {
    SynchronizationRequired,
    CommitRequired(Vec<String>),
    Published,
}

pub(super) fn managed_delivery_paths(root: &Path) -> Result<Vec<String>> {
    let policy = super::fingerprint::policy_file(root)?;
    let relative = policy
        .strip_prefix(root)
        .context("traffic policy is outside the target repository")?;
    Ok(vec![
        relative
            .to_str()
            .context("traffic policy path is not UTF-8")?
            .into(),
        PUBLIC_PROGRESS.into(),
    ])
}

pub(super) fn state(target_root: &Path, state: &RewriteState) -> Option<PublicationState> {
    workflow_complete(state)
        .then(|| inspect(target_root).unwrap_or(PublicationState::SynchronizationRequired))
}

pub(super) fn synchronize_if_complete(target_root: &Path, state: &RewriteState) -> Result<()> {
    if !workflow_complete(state) {
        return Ok(());
    }
    let path = target_root.join(PUBLIC_PROGRESS);
    let synchronized = verification_progress::synchronize(&path, VerificationStage::Progress)?;
    ensure!(
        synchronized || verification_progress::load(&path, VerificationStage::Progress)?.is_some(),
        "final verification progress is missing"
    );
    Ok(())
}

fn workflow_complete(state: &RewriteState) -> bool {
    state.phase == RewritePhase::SliceComplete
        && !state.api_inventory.is_empty()
        && state.api_inventory.iter().all(|item| {
            item.status == RewriteApiStatus::Skipped
                || (item.status == RewriteApiStatus::Complete && item.e2e_current)
        })
}

fn inspect(target_root: &Path) -> Result<PublicationState> {
    let path = target_root.join(PUBLIC_PROGRESS);
    let Some(report) = verification_progress::load(&path, VerificationStage::Progress)? else {
        return Ok(PublicationState::SynchronizationRequired);
    };
    if report.requires_persistence() {
        return Ok(PublicationState::SynchronizationRequired);
    }
    let uncommitted = git_uncommitted_managed_delivery_paths(target_root)?;
    if uncommitted.is_empty() {
        Ok(PublicationState::Published)
    } else {
        Ok(PublicationState::CommitRequired(uncommitted))
    }
}

fn git_uncommitted_managed_delivery_paths(target_root: &Path) -> Result<Vec<String>> {
    let mut uncommitted = Vec::new();
    for relative_path in managed_delivery_paths(target_root)? {
        if git_has_uncommitted_path(target_root, &relative_path)? {
            uncommitted.push(relative_path);
        }
    }
    Ok(uncommitted)
}

fn git_has_uncommitted_path(target_root: &Path, relative_path: &str) -> Result<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["status", "--porcelain=v1", "--untracked-files=normal", "--"])
        .arg(relative_path)
        .output()
        .with_context(|| {
            format!(
                "failed to inspect coordinator-managed delivery file {relative_path:?} in {}",
                target_root.display()
            )
        })?;
    ensure!(
        output.status.success(),
        "git status failed while inspecting coordinator-managed delivery file {relative_path:?} in {}",
        target_root.display()
    );
    Ok(!output.stdout.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;
    use crate::verification_progress::{
        ApiObservation, LatestCounts, ProgressObservation, ProgressReport, load, write,
    };

    #[test]
    fn reset_final_snapshot_is_rebuilt_before_commit_is_accepted() {
        let target = tempfile::tempdir().unwrap();
        git(target.path(), &["init"]);
        git(target.path(), &["config", "user.email", "test@example.com"]);
        git(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        write_progress(target.path(), &["replay-1", "replay-retry-1"]);
        git(target.path(), &["add", "."]);
        git(target.path(), &["commit", "-m", "baseline progress"]);

        let state = complete_state();
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::Published)
        );

        write_progress(target.path(), &["replay-1", "replay-retry-1", "replay-2"]);
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::CommitRequired(vec![
                PUBLIC_PROGRESS.to_string()
            ]))
        );
        assert_missing_batch_evidence(target.path(), &state);

        git(target.path(), &["restore", ".traffic-e2e/progress.yaml"]);
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::SynchronizationRequired)
        );
        synchronize_if_complete(target.path(), &state).unwrap();
        assert_eq!(
            load(
                &target.path().join(PUBLIC_PROGRESS),
                VerificationStage::Progress,
            )
            .unwrap()
            .unwrap()
            .totals
            .runs
            .executed,
            3
        );
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::CommitRequired(vec![
                PUBLIC_PROGRESS.to_string()
            ]))
        );

        git(target.path(), &["add", ".traffic-e2e/progress.yaml"]);
        git(target.path(), &["commit", "-m", "publish progress"]);
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::Published)
        );
        assert_missing_batch_evidence(target.path(), &state);
    }

    #[test]
    fn final_commit_includes_every_dirty_coordinator_managed_delivery_file() {
        let target = tempfile::tempdir().unwrap();
        git(target.path(), &["init"]);
        git(target.path(), &["config", "user.email", "test@example.com"]);
        git(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        write_managed_delivery_files(target.path(), "baseline");
        write_progress(target.path(), &["replay-1", "replay-retry-1"]);
        git(target.path(), &["add", "."]);
        git(target.path(), &["commit", "-m", "baseline delivery files"]);

        write_managed_delivery_files(target.path(), "updated");
        write_progress(target.path(), &["replay-1", "replay-retry-1", "replay-2"]);
        let state = complete_state();
        let expected = managed_delivery_paths(target.path()).unwrap();
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::CommitRequired(expected.clone()))
        );

        assert_missing_batch_evidence(target.path(), &state);

        git(target.path(), &["add", "."]);
        git(target.path(), &["commit", "-m", "publish delivery files"]);
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::Published)
        );
        assert_missing_batch_evidence(target.path(), &state);
    }

    // The publication state is independent of batch admission. A manually
    // completed API and a committed progress file cannot replace a real batch.
    fn assert_missing_batch_evidence(root: &Path, state: &RewriteState) {
        let action = super::super::action::envelope(
            root,
            state,
            super::super::action::state_action(root, state),
        );
        assert!(!action.terminal_allowed);
        match action.action {
            super::super::model::RewriteAction::InputRequired {
                reason: super::super::model::RewriteInputRequiredReason::RecordingEvidenceRequired,
                required,
                ..
            } => {
                assert!(!required.is_empty());
                assert!(
                    required
                        .iter()
                        .any(|requirement| requirement.contains("sealed Source run"))
                );
            }
            other => panic!("missing Source batch evidence must block publication: {other:?}"),
        }
    }

    fn complete_state() -> RewriteState {
        let mut state = super::super::test_state();
        super::super::inventory::install(&mut state, vec!["GET /api".to_string()]).unwrap();
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state.api_inventory[0].e2e_current = true;
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state
    }

    fn write_progress(target_root: &Path, keys: &[&str]) {
        let path = target_root.join(PUBLIC_PROGRESS);
        let mut report = ProgressReport::new(VerificationStage::Progress);
        for key in keys {
            report
                .apply(ProgressObservation {
                    key: (*key).to_string(),
                    evidence_fingerprint: format!("fingerprint-{key}"),
                    finished_at: format!("2026-08-14T00:00:0{}Z", key.len()),
                    finalized: true,
                    passed: None,
                    success_streak: None,
                    apis: BTreeMap::from([(
                        "GET /api".to_string(),
                        ApiObservation {
                            cases: LatestCounts {
                                executed: 1,
                                passed: 1,
                            },
                            finalized: true,
                            passed: true,
                            success_streak: None,
                        },
                    )]),
                })
                .unwrap();
        }
        write(&path, &report).unwrap();
    }

    fn write_managed_delivery_files(target_root: &Path, contents: &str) {
        let root = target_root.join(".traffic-e2e");
        fs::create_dir_all(&root).unwrap();
        for path in managed_delivery_paths(target_root).unwrap() {
            if path == PUBLIC_PROGRESS {
                continue;
            }
            fs::write(target_root.join(&path), format!("{contents}: {path}\n")).unwrap();
        }
    }

    fn git(target_root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(target_root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }
}
