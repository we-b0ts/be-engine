use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};

use super::action;
use super::artifacts;
use super::inventory;
use super::model::{
    RewriteActionEnvelope, RewritePhase, RewriteRecordingExecutionReport, RewriteRecordingKind,
    RewriteRecordingReason, RewriteRecordingSettings, RewriteState,
};
use super::store::RewriteStore;
use crate::{ManagedRecordingOperation, ManagedRecordingOptions, RecordingApi};

#[derive(Debug, Clone)]
pub struct RewriteRecordingRequestOptions {
    pub target_root: PathBuf,
    pub kind: RewriteRecordingKind,
    pub reason: RewriteRecordingReason,
    pub duration_seconds: NonZeroU64,
    pub per_api_case_limit: NonZeroUsize,
    pub replace_pending: bool,
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
    if inventory::initialize_legacy(&mut state) {
        store.save(&state)?;
    }
    ensure!(
        options.kind == RewriteRecordingKind::Standard,
        "only fresh standard recording requests are supported"
    );
    ensure!(
        state.phase != RewritePhase::SystemRepairRequired,
        "system repair must pass its coordinator-issued acceptance before requesting new traffic"
    );
    let settings = RewriteRecordingSettings {
        duration_seconds: options.duration_seconds,
        per_api_case_limit: options.per_api_case_limit,
    };
    if state.phase == RewritePhase::RecordingRequired {
        if artifacts::recording_manifest(&target_root, &state.recording_run_id).is_file() {
            return action::for_status(&target_root, &state);
        }
        if reuse_pending_recording(&state, options.reason, settings, options.replace_pending)? {
            return Ok(action::for_state(&target_root, &state));
        }
    }
    let run_id = artifacts::allocate_run_id_excluding(
        &target_root,
        ManagedRecordingOperation::Record,
        &[&state.recording_run_id],
    )?;
    reset_for_fresh_recording(&mut state, run_id, settings, options.reason);
    if state.recording_input_case_source.is_none() {
        state.recording_input_case_source = artifacts::compatible_recording_input(
            &target_root,
            &inventory::recording_scope(&state),
            Some(&state.recording_run_id),
        )?;
    }
    store.save(&state)?;
    Ok(action::for_state(&target_root, &state))
}

fn reuse_pending_recording(
    state: &RewriteState,
    reason: RewriteRecordingReason,
    settings: RewriteRecordingSettings,
    replace_pending: bool,
) -> Result<bool> {
    if state.recording_request_reason == Some(reason) && state.recording_settings == settings {
        return Ok(true);
    }
    ensure!(
        replace_pending,
        "a different standard recording is already pending; inspect `traffic-e2e rewrite status` or retry with --replace-pending"
    );
    Ok(false)
}

pub async fn execute_rewrite_recording(
    target_root: PathBuf,
    requested_action_id: &str,
) -> Result<RewriteRecordingExecutionReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let comparison = match state.phase {
        RewritePhase::RecordingRequired => false,
        RewritePhase::ComparisonRecordingRequired => true,
        _ => anyhow::bail!("rewrite workflow has no recording action to execute"),
    };
    let expected_action_id = action::recording_action_id(&state, comparison);
    ensure!(
        requested_action_id == expected_action_id,
        "recording action is stale or belongs to another workflow revision"
    );
    let (operation, run_id, manifest) = if comparison {
        let run_id = state
            .comparison_run_id
            .clone()
            .context("comparison recording action has no run id")?;
        (
            ManagedRecordingOperation::RecordComparison,
            run_id.clone(),
            artifacts::comparison_manifest(&target_root, &run_id),
        )
    } else {
        (
            ManagedRecordingOperation::Record,
            state.recording_run_id.clone(),
            artifacts::recording_manifest(&target_root, &state.recording_run_id),
        )
    };
    if manifest.is_file() {
        if comparison {
            artifacts::validate_comparison_recording(&target_root, &state)?;
        } else {
            artifacts::validate_standard_recording(&target_root, &state)?;
        }
        return Ok(execution_report(
            &target_root,
            requested_action_id,
            operation,
            run_id,
            manifest,
            true,
        ));
    }
    let request_source = if comparison {
        state.case_source.clone()
    } else {
        state.recording_input_case_source.clone()
    }
    .context("coordinator has no finalized real-traffic request corpus for the recording action")?;
    let apis = if comparison {
        vec![state.api.parse::<RecordingApi>()?]
    } else {
        inventory::recording_scope(&state)
            .iter()
            .map(|api| api.parse::<RecordingApi>())
            .collect::<Result<Vec<_>>>()?
    };
    let result = crate::run_managed_recording(ManagedRecordingOptions {
        target_root: target_root.clone(),
        operation,
        run_id: Some(run_id.clone()),
        duration_seconds: state.recording_settings.duration_seconds,
        baseline_recheck: comparison,
        breeze_no_fallback: true,
        apis,
        per_api_case_limit: Some(state.recording_settings.per_api_case_limit),
        request_source: Some(request_source),
    })
    .await?;
    Ok(execution_report(
        &target_root,
        requested_action_id,
        operation,
        run_id,
        result.manifest,
        false,
    ))
}

fn execution_report(
    target_root: &std::path::Path,
    action_id: &str,
    operation: ManagedRecordingOperation,
    run_id: String,
    manifest: PathBuf,
    already_completed: bool,
) -> RewriteRecordingExecutionReport {
    RewriteRecordingExecutionReport {
        action_id: action_id.to_string(),
        run_id,
        operation: match operation {
            ManagedRecordingOperation::Record => "record".to_string(),
            ManagedRecordingOperation::RecordComparison => "record_comparison".to_string(),
        },
        already_completed,
        manifest,
        next: action::next_command(target_root),
    }
}

pub(super) fn reset_for_fresh_recording(
    state: &mut RewriteState,
    run_id: String,
    settings: RewriteRecordingSettings,
    reason: RewriteRecordingReason,
) {
    state.recording_input_case_source = state
        .case_source
        .clone()
        .or_else(|| state.recording_input_case_source.clone());
    state.phase = RewritePhase::RecordingRequired;
    inventory::reset_for_recording(state);
    state.recording_run_id = run_id;
    state.recording_rejection = None;
    state.recording_settings = settings;
    state.recording_request_reason = Some(reason);
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    state.case_source = None;
    state.case_inventory_id = None;
    state.source_revision = None;
    state.group_id = None;
    state.target_fingerprint = None;
    state.attempts.clear();
    state.attempt_delta = None;
    state.active_issue = None;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
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
    fn fresh_request_invalidates_evidence_and_returns_opaque_managed_action() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::SliceComplete;
        state.case_source = Some(PathBuf::from("old-cases"));
        state.case_inventory_id = Some("old-inventory".to_string());
        state.group_id = Some("GET /api".to_string());
        state.comparison_run_id = Some("20260802000001".to_string());
        state.e2e_current = true;
        state.comparison_current = true;

        reset_for_fresh_recording(
            &mut state,
            "20260802000002".to_string(),
            RewriteRecordingSettings {
                duration_seconds: NonZeroU64::new(90).unwrap(),
                per_api_case_limit: NonZeroUsize::new(250).unwrap(),
            },
            RewriteRecordingReason::UserRequested,
        );

        assert_eq!(state.phase, RewritePhase::RecordingRequired);
        assert!(state.case_source.is_none());
        assert!(state.case_inventory_id.is_none());
        assert!(state.group_id.is_none());
        assert!(state.comparison_run_id.is_none());
        assert!(!state.e2e_current);
        assert!(!state.comparison_current);
        let target = tempfile::tempdir().unwrap();
        let action = action::for_state(target.path(), &state).action;
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
                "rewrite",
                "recording",
                "execute",
                action::recording_action_id(&state, false).as_str(),
            ]
        );
        assert_eq!(command.cwd, target.path());
        assert_eq!(
            state.recording_input_case_source,
            Some(PathBuf::from("old-cases"))
        );
        assert_eq!(
            summary,
            "fresh standard recording requested (user_requested) for GET /api"
        );
    }

    #[test]
    fn pending_request_is_idempotent_and_requires_explicit_replacement() {
        let mut state = crate::rewrite::test_state();
        state.recording_request_reason = Some(RewriteRecordingReason::UserRequested);
        let settings = state.recording_settings;

        assert!(
            reuse_pending_recording(
                &state,
                RewriteRecordingReason::UserRequested,
                settings,
                false,
            )
            .unwrap()
        );

        let different = RewriteRecordingSettings {
            duration_seconds: NonZeroU64::new(90).unwrap(),
            per_api_case_limit: settings.per_api_case_limit,
        };
        assert!(
            reuse_pending_recording(
                &state,
                RewriteRecordingReason::UserRequested,
                different,
                false,
            )
            .is_err()
        );
        assert!(
            !reuse_pending_recording(
                &state,
                RewriteRecordingReason::UserRequested,
                different,
                true,
            )
            .unwrap()
        );
    }
}
