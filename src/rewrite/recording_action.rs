use std::path::Path;

use anyhow::Result;

use super::model::{RewriteAction, RewriteCommandSpec, RewritePhase, RewriteState};
use super::recording_execution::RecordingExecutionState;
use super::{action, artifacts, fingerprint, inventory, recording, recording_execution};

pub(super) fn status_action(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    let (run_id, publication, label) = match state.phase {
        RewritePhase::RecordingRequired => (
            state.recording_run_id.as_str(),
            artifacts::standard_recording_publication(target_root, &state.recording_run_id)?,
            "standard",
        ),
        RewritePhase::ComparisonRecordingRequired => {
            let run_id = state
                .comparison_run_id
                .as_deref()
                .expect("comparison recording phase requires a run id");
            (
                run_id,
                artifacts::comparison_recording_publication(target_root, run_id)?,
                "comparison",
            )
        }
        _ => return Ok(None),
    };
    let execution = recording_execution::state(target_root)?;
    Ok(Some(match execution {
        RecordingExecutionState::Live(marker) => {
            let expected = recording_action_id(
                state,
                state.phase == RewritePhase::ComparisonRecordingRequired,
            );
            if marker.action_id != expected || marker.run_id != run_id {
                recovery_required(
                    target_root,
                    "recording executor does not match the current coordinator action",
                )
            } else {
                RewriteAction::RecordingInProgress {
                    summary: format!(
                        "{label} recording run {run_id} is executing under coordinator ownership"
                    ),
                    run_id: run_id.to_string(),
                    status_poll_after_seconds: recording::STATUS_POLL_AFTER_SECONDS,
                    status: action::status_command(target_root),
                }
            }
        }
        RecordingExecutionState::Stale(_) => recovery_required(
            target_root,
            "recording executor stopped before coordinator completion",
        ),
        RecordingExecutionState::Absent => match publication {
            artifacts::RecordingPublication::Finalized => RewriteAction::AdvanceRequired {
                summary: format!(
                    "{label} recording result for run {run_id} is finalized; advance coordinator validation"
                ),
                command: action::next_command_for_api(target_root, &state.api),
            },
            artifacts::RecordingPublication::Running => recovery_required(
                target_root,
                "recording manifest is still running but no executor owns it",
            ),
            artifacts::RecordingPublication::Missing => return Ok(None),
        },
    }))
}

fn recovery_required(target_root: &Path, reason: &str) -> RewriteAction {
    RewriteAction::RecoveryRequired {
        summary: format!("{reason}; recover the managed recording before continuing"),
        command: action::recover_command(target_root),
    }
}

pub(super) fn recording_action_id(state: &RewriteState, comparison: bool) -> String {
    let run_id = if comparison {
        state
            .comparison_run_id
            .as_deref()
            .expect("comparison action requires run id")
    } else {
        &state.recording_run_id
    };
    let input_source = if comparison {
        state.case_source.as_deref()
    } else {
        recording::standard_recording_input_source(state)
    };
    let input_source = input_source
        .map(|path| path.to_string_lossy())
        .unwrap_or_default();
    format!(
        "recording-{}",
        fingerprint::id(&[
            &state.workflow_id,
            if comparison { "comparison" } else { "standard" },
            run_id,
            &inventory::recording_scope(state).join("\n"),
            &state.recording_settings.duration_seconds.to_string(),
            &state.recording_settings.per_api_case_limit.to_string(),
            input_source.as_ref(),
        ])
        .trim_start_matches("fnv1a64:")
    )
}

pub(super) fn command(
    target_root: &Path,
    state: &RewriteState,
    comparison: bool,
) -> RewriteCommandSpec {
    action::command(
        target_root,
        vec![
            "recording".to_string(),
            "execute".to_string(),
            recording_action_id(state, comparison),
        ],
        Vec::new(),
    )
}
