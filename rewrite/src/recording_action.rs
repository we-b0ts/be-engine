//! Read-only observation of external recording publication.
use super::{
    action, artifacts,
    model::{RewriteAction, RewritePhase, RewriteRecordingProgress, RewriteState},
};
use anyhow::Result;
use std::path::Path;

pub(super) fn status_action(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    let (run_id, recording_status) = match state.phase {
        RewritePhase::RecordingRequired if !state.recording_run_id.is_empty() => (
            state.recording_run_id.as_str(),
            artifacts::standard_recording_status(target_root, &state.recording_run_id)?,
        ),
        _ => return Ok(None),
    };
    Ok(match recording_status.publication {
        artifacts::RecordingPublication::Missing => None,
        artifacts::RecordingPublication::Finalized if state.recording_rejection.is_none() => {
            Some(RewriteAction::AdvanceRequired {
                api: (!state.api.is_empty())
                    .then(|| super::api_selector::public_api(&state.api).into()),
                kind: super::model::RewriteAdvanceKind::Workflow,
                summary: format!("external recording {run_id} is finalized; validate its evidence"),
                command: action::next_command(target_root),
            })
        }
        artifacts::RecordingPublication::Finalized => None,
        artifacts::RecordingPublication::Running => Some(RewriteAction::RecordingInProgress {
            summary: format!(
                "external recording {run_id} has not finalized; rewrite does not own its process"
            ),
            run_id: run_id.to_owned(),
            progress: RewriteRecordingProgress {
                apis: recording_status.progress.apis,
                published_cases: recording_status.progress.published_cases,
                failed_cases: recording_status.progress.failed_cases,
            },
            status_poll_after_seconds: 30,
            status: action::status_command(target_root),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn external_publication_is_observed_without_process_ownership_or_artifact_writes() {
        let target = tempfile::tempdir().unwrap();
        let state = crate::test_state();
        let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        let running = br#"{"status":"running","recording_apis":["GET /api"],"published_cases":1}"#;
        fs::write(&manifest, running).unwrap();
        assert!(matches!(
            status_action(target.path(), &state).unwrap(),
            Some(RewriteAction::RecordingInProgress { progress, .. }) if progress.published_cases == 1
        ));
        assert_eq!(fs::read(&manifest).unwrap(), running);
        fs::write(
            &manifest,
            br#"{"status":"completed","recording_apis":["GET /api"],"published_cases":1}"#,
        )
        .unwrap();
        assert!(matches!(
            status_action(target.path(), &state).unwrap(),
            Some(RewriteAction::AdvanceRequired { .. })
        ));
        assert_eq!(
            fs::read_dir(manifest.parent().unwrap().parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }
}
