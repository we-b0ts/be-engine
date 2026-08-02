use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};

use super::action;
use super::artifacts;
use super::model::{
    RewriteActionEnvelope, RewritePhase, RewriteRecordingKind, RewriteRecordingReason,
    RewriteRecordingSettings, RewriteState,
};
use super::store::RewriteStore;
use crate::ManagedRecordingOperation;

#[derive(Debug, Clone)]
pub struct RewriteRecordingRequestOptions {
    pub target_root: PathBuf,
    pub kind: RewriteRecordingKind,
    pub reason: RewriteRecordingReason,
    pub duration_seconds: NonZeroU64,
    pub case_limit: NonZeroUsize,
}

pub fn request_rewrite_recording(
    options: RewriteRecordingRequestOptions,
) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    ensure!(
        options.kind == RewriteRecordingKind::Standard,
        "only fresh standard recording requests are supported"
    );
    let run_id = artifacts::allocate_run_id_excluding(
        &target_root,
        ManagedRecordingOperation::Record,
        &[&state.recording_run_id],
    )?;
    reset_for_fresh_recording(
        &mut state,
        run_id,
        RewriteRecordingSettings {
            duration_seconds: options.duration_seconds,
            case_limit: options.case_limit,
        },
        options.reason,
    );
    store.save(&state)?;
    Ok(action::for_state(&state))
}

fn reset_for_fresh_recording(
    state: &mut RewriteState,
    run_id: String,
    settings: RewriteRecordingSettings,
    reason: RewriteRecordingReason,
) {
    state.phase = RewritePhase::RecordingRequired;
    state.recording_run_id = run_id;
    state.recording_rejection = None;
    state.recording_settings = settings;
    state.recording_request_reason = Some(reason);
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    state.case_source = None;
    state.source_revision = None;
    state.group_id = None;
    state.target_fingerprint = None;
    state.attempts.clear();
    state.attempt_delta = None;
    state.active_issue = None;
    state.rule_plan = None;
    state.route = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RewriteAction;

    #[test]
    fn fresh_request_invalidates_evidence_and_returns_exact_parameters() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::SliceComplete;
        state.case_source = Some(PathBuf::from("old-cases"));
        state.group_id = Some("GET /api".to_string());
        state.comparison_run_id = Some("20260802000001".to_string());
        state.e2e_current = true;
        state.comparison_current = true;

        reset_for_fresh_recording(
            &mut state,
            "20260802000002".to_string(),
            RewriteRecordingSettings {
                duration_seconds: NonZeroU64::new(90).unwrap(),
                case_limit: NonZeroUsize::new(250).unwrap(),
            },
            RewriteRecordingReason::UserRequested,
        );

        assert_eq!(state.phase, RewritePhase::RecordingRequired);
        assert!(state.case_source.is_none());
        assert!(state.group_id.is_none());
        assert!(state.comparison_run_id.is_none());
        assert!(!state.e2e_current);
        assert!(!state.comparison_current);
        let action = action::for_state(&state).action;
        let RewriteAction::RecordingRequired {
            summary, command, ..
        } = action
        else {
            panic!("expected a standard recording action");
        };
        assert_eq!(
            command.argv,
            [
                "traffic-e2e",
                "record",
                "--target-root",
                ".",
                "--run-id",
                "20260802000002",
                "--duration-seconds",
                "90",
                "--api",
                "GET /api",
                "--case-limit",
                "250",
            ]
        );
        assert_eq!(
            summary,
            "fresh standard recording requested (user_requested) for GET /api"
        );
    }
}
