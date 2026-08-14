use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::model::{RewriteApiStatus, RewritePhase, RewriteState};
use crate::verification_progress::{self, VerificationStage};

const PUBLIC_PROGRESS: [(&str, VerificationStage); 2] = [
    (
        ".traffic-e2e/replay-progress.yaml",
        VerificationStage::Replay,
    ),
    (
        ".traffic-e2e/comparison-progress.yaml",
        VerificationStage::Comparison,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationState {
    SynchronizationRequired,
    CommitRequired,
    Published,
}

pub(super) fn public_paths() -> [&'static str; 2] {
    PUBLIC_PROGRESS.map(|(path, _)| path)
}

pub(super) fn state(target_root: &Path, state: &RewriteState) -> Option<PublicationState> {
    workflow_complete(state)
        .then(|| inspect(target_root).unwrap_or(PublicationState::SynchronizationRequired))
}

pub(super) fn synchronize_if_complete(target_root: &Path, state: &RewriteState) -> Result<()> {
    if !workflow_complete(state) {
        return Ok(());
    }
    for (relative, stage) in PUBLIC_PROGRESS {
        let path = target_root.join(relative);
        let synchronized = verification_progress::synchronize(&path, stage)?;
        ensure!(
            synchronized || verification_progress::load(&path, stage)?.is_some(),
            "final {:?} progress is missing",
            stage
        );
    }
    Ok(())
}

fn workflow_complete(state: &RewriteState) -> bool {
    state.phase == RewritePhase::SliceComplete
        && !state.api_inventory.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete)
}

fn inspect(target_root: &Path) -> Result<PublicationState> {
    for (relative, stage) in PUBLIC_PROGRESS {
        let path = target_root.join(relative);
        let Some(report) = verification_progress::load(&path, stage)? else {
            return Ok(PublicationState::SynchronizationRequired);
        };
        if report.requires_persistence() {
            return Ok(PublicationState::SynchronizationRequired);
        }
    }
    if git_has_uncommitted_progress(target_root)? {
        Ok(PublicationState::CommitRequired)
    } else {
        Ok(PublicationState::Published)
    }
}

fn git_has_uncommitted_progress(target_root: &Path) -> Result<bool> {
    let relative_paths = public_paths();
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["status", "--porcelain=v1", "--untracked-files=normal", "--"])
        .args(relative_paths)
        .output()
        .with_context(|| {
            format!(
                "failed to inspect final verification progress in {}",
                target_root.display()
            )
        })?;
    ensure!(
        output.status.success(),
        "git status failed while inspecting final verification progress in {}",
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
        write_progress(target.path(), VerificationStage::Replay, &["replay-1"]);
        write_progress(
            target.path(),
            VerificationStage::Comparison,
            &["comparison-1"],
        );
        git(target.path(), &["add", "."]);
        git(target.path(), &["commit", "-m", "baseline progress"]);

        let state = complete_state();
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::Published)
        );

        write_progress(
            target.path(),
            VerificationStage::Replay,
            &["replay-1", "replay-2"],
        );
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::CommitRequired)
        );
        let commit_action =
            serde_json::to_value(super::super::action::for_state(target.path(), &state)).unwrap();
        assert_eq!(
            commit_action.pointer("/action/kind"),
            Some(&serde_json::json!("input_required"))
        );
        assert_eq!(
            commit_action.pointer("/action/details/reason"),
            Some(&serde_json::json!("verification_progress_commit_required"))
        );
        assert_eq!(commit_action["terminal_allowed"], false);

        git(
            target.path(),
            &["restore", ".traffic-e2e/replay-progress.yaml"],
        );
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::SynchronizationRequired)
        );
        synchronize_if_complete(target.path(), &state).unwrap();
        assert_eq!(
            load(
                &target.path().join(PUBLIC_PROGRESS[0].0),
                VerificationStage::Replay,
            )
            .unwrap()
            .unwrap()
            .totals
            .runs
            .executed,
            2
        );
        assert_eq!(
            super::state(target.path(), &state),
            Some(PublicationState::CommitRequired)
        );

        git(target.path(), &["add", ".traffic-e2e/replay-progress.yaml"]);
        git(target.path(), &["commit", "-m", "publish progress"]);
        let published = super::super::action::for_state(target.path(), &state);
        assert!(published.terminal_allowed);
        assert_eq!(
            serde_json::to_value(published).unwrap()["action"]["kind"],
            "complete"
        );
    }

    fn complete_state() -> RewriteState {
        let mut state = super::super::test_state();
        super::super::inventory::install(&mut state, vec!["GET /api".to_string()]).unwrap();
        state.api_inventory[0].status = RewriteApiStatus::Complete;
        state.phase = RewritePhase::SliceComplete;
        state.e2e_current = true;
        state.comparison_current = true;
        state
    }

    fn write_progress(target_root: &Path, stage: VerificationStage, keys: &[&str]) {
        let path = target_root.join(match stage {
            VerificationStage::Replay => PUBLIC_PROGRESS[0].0,
            VerificationStage::Comparison => PUBLIC_PROGRESS[1].0,
        });
        let mut report = ProgressReport::new(stage);
        for key in keys {
            report
                .apply(ProgressObservation {
                    key: (*key).to_string(),
                    evidence_fingerprint: format!("fingerprint-{key}"),
                    finished_at: format!("2026-08-14T00:00:0{}Z", key.len()),
                    apis: BTreeMap::from([(
                        "GET /api".to_string(),
                        ApiObservation {
                            cases: LatestCounts {
                                executed: 1,
                                passed: 1,
                            },
                            passed: true,
                        },
                    )]),
                })
                .unwrap();
        }
        write(&path, &report).unwrap();
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
