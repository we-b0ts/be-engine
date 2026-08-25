use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteActionEnvelope, RewriteCommandSpec, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
    RewritePhase, RewriteRecordingReason, RewriteRepairAcceptanceKind, RewriteRouteRecord,
    RewriteRouteReport, RewriteState,
};
use super::store::RewriteStore;
use super::{
    action, artifacts, evidence, fingerprint, inventory, recording, traffic_operation, worker,
};
use crate::{E2eRunContext, ManagedRecordingOperation, RecordingApi, RewriteContext};

#[derive(Debug, Clone)]
pub(super) struct SystemRepairRouteOptions {
    pub kind: String,
    pub evidence_id: String,
    pub source_ref: String,
    pub required_change: String,
}

#[derive(Debug, Clone)]
pub struct RewriteRepairCancelOptions {
    pub target_root: PathBuf,
    pub repair_id: String,
    pub reason: String,
    pub confirm_misroute: bool,
}

#[derive(Debug, Clone)]
pub struct RewriteReplayRetryOptions {
    pub target_root: PathBuf,
    pub api: String,
    pub failed_attempt: u64,
    pub out_of_band_attempt: u64,
    pub reason: String,
    pub confirm_out_of_band_run: bool,
}

pub(super) fn route(
    target_root: &Path,
    state: &mut RewriteState,
    options: SystemRepairRouteOptions,
) -> Result<RewriteRouteReport> {
    ensure!(
        state.phase == super::model::RewritePhase::ImplementationRequired,
        "rewrite route is valid only for the active implementation issue"
    );
    let mut issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_single_line("route source reference", &options.source_ref)?;
    validate_single_line("required system change", &options.required_change)?;
    validate_route_kind(&issue, &options.kind)?;
    let valid_evidence = evidence::commands(target_root, state)
        .into_iter()
        .any(|command| {
            evidence::query(target_root, state, &command.query_id)
                .is_ok_and(|report| report.evidence_id == options.evidence_id)
        });
    ensure!(
        valid_evidence,
        "route evidence is stale or belongs to another issue"
    );
    let (acceptance_kind, observed_revision) = acceptance_snapshot(target_root, &options.kind)?;
    let repair_id = repair_id(
        state,
        &issue,
        &options.kind,
        &options.evidence_id,
        acceptance_kind,
        &observed_revision,
    );
    let route = RewriteRouteRecord {
        kind: options.kind,
        evidence_id: options.evidence_id,
        source_ref: options.source_ref,
        required_change: options.required_change,
        repair_id: Some(repair_id.clone()),
        acceptance_kind: Some(acceptance_kind),
        observed_revision: Some(observed_revision),
        legacy_acceptance_command: None,
    };
    issue.owner = match route.kind.as_str() {
        "recorder_capability_gap" | "replay_capability_gap" => RewriteIssueOwner::TrafficE2eSystem,
        _ => RewriteIssueOwner::SourceInvestigation,
    };
    state.active_issue = Some(issue.clone());
    state.route = Some(route.clone());
    state.phase = super::model::RewritePhase::SystemRepairRequired;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.bump();
    Ok(RewriteRouteReport {
        accepted: true,
        issue_id: issue.id,
        route,
        acceptance: action::repair_verify_command(target_root, &repair_id),
    })
}

pub(super) fn verify(
    target_root: &Path,
    state: &mut RewriteState,
    requested_id: &str,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        state.phase == super::model::RewritePhase::SystemRepairRequired,
        "rewrite workflow has no system repair awaiting verification"
    );
    let route = state
        .route
        .clone()
        .context("system repair has no accepted route")?;
    ensure!(
        route.repair_id.as_deref() == Some(requested_id),
        "repair acceptance is stale or belongs to another issue"
    );
    let acceptance_kind = route
        .acceptance_kind
        .context("system repair acceptance has not been initialized")?;
    let observed_revision = route
        .observed_revision
        .as_deref()
        .context("system repair acceptance has no observed revision")?;
    let current_revision = current_revision(target_root, acceptance_kind)?;
    ensure!(
        current_revision != observed_revision,
        "required system repair has not changed the coordinator-verified revision"
    );

    match route.kind.as_str() {
        "recorder_capability_gap" => {
            let run_id = artifacts::allocate_run_id_excluding(
                target_root,
                ManagedRecordingOperation::Record,
                &[&state.recording_run_id],
            )?;
            recording::reset_for_fresh_recording(
                state,
                run_id,
                state.recording_settings,
                RewriteRecordingReason::RecorderContractChanged,
            );
        }
        "source_change" => {
            let run_id = artifacts::allocate_run_id_excluding(
                target_root,
                ManagedRecordingOperation::Record,
                &[&state.recording_run_id],
            )?;
            recording::reset_for_fresh_recording(
                state,
                run_id,
                state.recording_settings,
                RewriteRecordingReason::SourceBaselineChanged,
            );
        }
        "replay_capability_gap" | "external_data_blocker" => {
            state.phase = super::model::RewritePhase::ImplementationRequired;
            state.target_fingerprint = None;
            state.route = None;
            state.rule_plan = None;
            state.dependency_rule_plan = None;
            state.recorder_capture_plan = None;
            state.e2e_current = false;
            state.comparison_current = false;
            state.bump();
            return Ok(action::advance_envelope(
                target_root,
                state,
                "system repair was accepted; rerun the same immutable cases".to_string(),
            ));
        }
        kind => anyhow::bail!("unsupported repair route kind {kind:?}"),
    }
    action::for_status(target_root, state)
}

pub fn resume_rewrite_replay_planning(
    context: RewriteContext,
    requested_id: &str,
) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_repair(&state, requested_id)
        .context("repair migration is stale or belongs to no concurrent API work item")?;
    if state.api != api {
        let requested_api = api.parse::<RecordingApi>()?;
        inventory::activate_requested(&mut state, Some(&requested_api))?;
    }
    let report = resume_replay_planning(&target_root, &mut state, requested_id)?;
    store.save(&state)?;
    Ok(report)
}

pub fn cancel_misrouted_rewrite_repair(
    options: RewriteRepairCancelOptions,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        options.confirm_misroute,
        "canceling a misrouted repair requires --confirm-misroute"
    );
    validate_single_line("repair cancellation reason", &options.reason)?;
    ensure!(
        options.reason.len() <= 500,
        "repair cancellation reason must not exceed 500 bytes"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let api = inventory::api_for_repair(&state, &options.repair_id)
        .context("repair cancellation is stale or belongs to no concurrent API work item")?;
    if state.api != api {
        let requested_api = api.parse::<RecordingApi>()?;
        inventory::activate_requested(&mut state, Some(&requested_api))?;
    }
    let report = cancel_misroute(
        &target_root,
        &mut state,
        &options.repair_id,
        &options.reason,
    )?;
    store.save(&state)?;
    Ok(report)
}

pub fn retry_rewrite_replay_after_out_of_band_run(
    options: RewriteReplayRetryOptions,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        options.confirm_out_of_band_run,
        "retrying Replay after an out-of-band run requires --confirm-out-of-band-run"
    );
    validate_single_line("out-of-band Replay recovery reason", &options.reason)?;
    ensure!(
        options.reason.len() <= 500,
        "out-of-band Replay recovery reason must not exceed 500 bytes"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    ensure!(
        matches!(
            traffic_operation::state(&target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "cannot recover out-of-band Replay state while a traffic operation is active or stale"
    );
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    ensure!(
        state.api == options.api,
        "out-of-band Replay recovery targets API {:?}, but the active API is {:?}",
        options.api,
        state.api
    );
    worker::ensure_api_confirmed(&state, &options.api, "recovering out-of-band Replay state")?;
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no focused case source")?;
    let observed = crate::e2e_run::finalized_focused_attempt_summary(
        E2eRunContext {
            target_root: target_root.clone(),
            case_source,
            run_key: None,
        },
        &options.api,
    )?;
    let action = retry_replay_after_out_of_band_run(&target_root, &mut state, &options, &observed)?;
    store.save(&state)?;
    Ok(action)
}

fn retry_replay_after_out_of_band_run(
    target_root: &Path,
    state: &mut RewriteState,
    options: &RewriteReplayRetryOptions,
    observed: &crate::e2e_run::E2eFocusedAttemptSummary,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        state.phase == RewritePhase::ImplementationRequired,
        "rewrite workflow has no implementation failure eligible for Replay retry"
    );
    ensure!(
        state.route.is_none()
            && state.rule_plan.is_none()
            && state.dependency_rule_plan.is_none()
            && state.recorder_capture_plan.is_none(),
        "rewrite workflow has a pending repair or rule transition; execute its coordinator command instead"
    );
    let issue = state
        .active_issue
        .as_ref()
        .context("rewrite workflow has no active implementation issue")?;
    let current_attempt = state
        .attempts
        .last()
        .context("rewrite workflow has no failed focused attempt")?;
    ensure!(
        !current_attempt.passed
            && current_attempt.attempt == options.failed_attempt
            && issue.attempt == options.failed_attempt,
        "failed attempt does not match the active coordinator issue"
    );
    ensure!(
        observed.attempt == options.out_of_band_attempt
            && observed.attempt > options.failed_attempt
            && observed.passed,
        "the declared out-of-band attempt is not the newer passing focused result"
    );
    ensure!(
        state.case_source.as_ref() == Some(&observed.case_source)
            && state.case_inventory_id.as_ref() == Some(&observed.case_inventory_id),
        "out-of-band focused evidence does not match the coordinator case source and inventory"
    );
    let current_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    ensure!(
        state.target_fingerprint.as_deref() == Some(current_target_fingerprint.as_str())
            && issue.observed_target_fingerprint == current_target_fingerprint,
        "target repository changed after the failed coordinator attempt; use the normal target quality and acceptance flow"
    );

    state.target_fingerprint = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(action::advance_envelope(
        target_root,
        state,
        format!(
            "administrator discarded out-of-band focused attempt {} and re-armed coordinator Replay after attempt {}: {}",
            options.out_of_band_attempt, options.failed_attempt, options.reason
        ),
    ))
}

fn cancel_misroute(
    target_root: &Path,
    state: &mut RewriteState,
    requested_id: &str,
    reason: &str,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        state.phase == RewritePhase::SystemRepairRequired,
        "rewrite workflow has no system repair eligible for cancellation"
    );
    let route = state
        .route
        .as_ref()
        .context("system repair has no accepted route")?;
    ensure!(
        route.repair_id.as_deref() == Some(requested_id),
        "repair cancellation is stale or belongs to another issue"
    );
    let issue_kind = state
        .active_issue
        .as_ref()
        .context("system repair has no active issue")?
        .kind;
    ensure!(
        repair_can_return_to_target(&route.kind, issue_kind),
        "only a misrouted source-change or Recorder/Replay capability repair can be returned to target implementation"
    );
    let issue = state
        .active_issue
        .as_mut()
        .context("system repair has no active issue")?;
    issue.owner = RewriteIssueOwner::TargetCode;
    state.phase = RewritePhase::ImplementationRequired;
    state.route = None;
    state.bump();
    Ok(action::advance_envelope(
        target_root,
        state,
        format!("administrator canceled misrouted repair {requested_id}: {reason}"),
    ))
}

fn repair_can_return_to_target(route_kind: &str, issue_kind: RewriteIssueKind) -> bool {
    match route_kind {
        "source_change" => issue_kind == RewriteIssueKind::Comparison,
        "replay_capability_gap" => matches!(
            issue_kind,
            RewriteIssueKind::Replay | RewriteIssueKind::Dependency
        ),
        "recorder_capability_gap" => matches!(
            issue_kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency
        ),
        _ => false,
    }
}

fn resume_replay_planning(
    target_root: &Path,
    state: &mut RewriteState,
    requested_id: &str,
) -> Result<RewriteActionEnvelope> {
    ensure!(
        state.phase == RewritePhase::SystemRepairRequired,
        "rewrite workflow has no system repair eligible for replay planning"
    );
    let route = state
        .route
        .as_ref()
        .context("system repair has no accepted route")?;
    ensure!(
        route.repair_id.as_deref() == Some(requested_id),
        "repair migration is stale or belongs to another issue"
    );
    ensure!(
        replay_planning_migration_is_available(state),
        "repair route is not an external-data response blocker eligible for replay planning"
    );
    state.phase = RewritePhase::ImplementationRequired;
    state.target_fingerprint = None;
    state.route = None;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(action::advance_envelope(
        target_root,
        state,
        "legacy external-data blocker migrated to bootstrap replay planning".to_string(),
    ))
}

pub(super) fn pending_command(
    target_root: &Path,
    state: &RewriteState,
) -> Option<RewriteCommandSpec> {
    let repair_id = state.route.as_ref()?.repair_id.as_deref()?;
    if replay_planning_migration_is_available(state) {
        return Some(action::command(
            target_root,
            vec![
                "repair".to_string(),
                "resume-replay-planning".to_string(),
                repair_id.to_string(),
            ],
            Vec::new(),
        ));
    }
    Some(action::repair_verify_command(target_root, repair_id))
}

fn replay_planning_migration_is_available(state: &RewriteState) -> bool {
    state
        .route
        .as_ref()
        .is_some_and(|route| route.kind == "external_data_blocker")
        && state
            .active_issue
            .as_ref()
            .is_some_and(|issue| issue.kind == RewriteIssueKind::Response)
}

pub(super) fn initialize_legacy_acceptance(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if state.phase != super::model::RewritePhase::SystemRepairRequired {
        return Ok(false);
    }
    let Some(route) = state.route.as_ref() else {
        return Ok(false);
    };
    if route.repair_id.is_some() {
        return Ok(false);
    }
    let issue = state
        .active_issue
        .as_ref()
        .context("legacy system repair has no active issue")?;
    let (acceptance_kind, observed_revision) = acceptance_snapshot(target_root, &route.kind)?;
    let repair_id = repair_id(
        state,
        issue,
        &route.kind,
        &route.evidence_id,
        acceptance_kind,
        &observed_revision,
    );
    let route = state
        .route
        .as_mut()
        .expect("legacy route disappeared during migration");
    route.repair_id = Some(repair_id);
    route.acceptance_kind = Some(acceptance_kind);
    route.observed_revision = Some(observed_revision);
    route.legacy_acceptance_command = None;
    state.bump();
    Ok(true)
}

fn acceptance_snapshot(
    target_root: &Path,
    route_kind: &str,
) -> Result<(RewriteRepairAcceptanceKind, String)> {
    let kind = match route_kind {
        "recorder_capability_gap" | "replay_capability_gap" => {
            RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged
        }
        "source_change" => RewriteRepairAcceptanceKind::SourceRevisionChanged,
        "external_data_blocker" => RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged,
        kind => anyhow::bail!("unsupported repair route kind {kind:?}"),
    };
    Ok((kind, current_revision(target_root, kind)?))
}

fn current_revision(target_root: &Path, kind: RewriteRepairAcceptanceKind) -> Result<String> {
    match kind {
        RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged => {
            fingerprint::traffic_e2e_revision()
        }
        RewriteRepairAcceptanceKind::SourceRevisionChanged => {
            let (_, project) = crate::e2e_run::resolve_project(target_root)?;
            fingerprint::source_container_revision(&project.source_container)
        }
        RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged => {
            let (_, project) = crate::e2e_run::resolve_project(target_root)?;
            fingerprint::source_runtime_inputs_revision(target_root, &project.source_container)
        }
    }
}

fn repair_id(
    state: &RewriteState,
    issue: &RewriteIssue,
    route_kind: &str,
    evidence_id: &str,
    acceptance_kind: RewriteRepairAcceptanceKind,
    observed_revision: &str,
) -> String {
    format!(
        "repair-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &issue.id,
            route_kind,
            evidence_id,
            &format!("{acceptance_kind:?}"),
            observed_revision,
        ])
        .trim_start_matches("fnv1a64:")
    )
}

fn validate_route_kind(issue: &RewriteIssue, kind: &str) -> Result<()> {
    let allowed = match kind {
        "replay_capability_gap" => matches!(
            issue.kind,
            RewriteIssueKind::Replay | RewriteIssueKind::Dependency
        ),
        "recorder_capability_gap" => matches!(
            issue.kind,
            RewriteIssueKind::Response | RewriteIssueKind::Dependency
        ),
        "external_data_blocker" => issue.kind == RewriteIssueKind::Response,
        "source_change" => issue.kind == RewriteIssueKind::Comparison,
        _ => false,
    };
    ensure!(
        allowed,
        "route kind {kind:?} is not valid for active issue {:?}",
        issue.kind
    );
    Ok(())
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;
    use crate::rewrite::model::{RewriteAttemptSummary, RewriteIssueOwner, RewritePhase};
    use crate::{
        E2eDependencyGate, E2eDiagnosisCounts, E2eReplayGate, E2eResponseGate, E2eVerificationGates,
    };

    #[test]
    fn repair_verification_rejects_stale_ids_and_unchanged_revisions() {
        let target = tempfile::tempdir().unwrap();
        let revision = fingerprint::traffic_e2e_revision().unwrap();
        let mut state = repair_state(revision);

        assert!(verify(target.path(), &mut state, "repair-stale").is_err());
        assert!(verify(target.path(), &mut state, "repair-current").is_err());
        assert_eq!(state.phase, RewritePhase::SystemRepairRequired);
    }

    #[test]
    fn coordinator_verified_revision_change_returns_to_the_same_cases() {
        let target = tempfile::tempdir().unwrap();
        let mut state = repair_state("fnv1a64:old".to_string());

        let action = verify(target.path(), &mut state, "repair-current").unwrap();

        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert!(state.route.is_none());
        assert!(state.target_fingerprint.is_none());
        assert!(matches!(
            action.action,
            super::super::model::RewriteAction::AdvanceRequired { .. }
        ));
    }

    #[test]
    fn legacy_external_data_response_blocker_resumes_replay_planning_without_revision_change() {
        let target = tempfile::tempdir().unwrap();
        let mut state = repair_state("unchanged-runtime-inputs".to_string());
        state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
        state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
        state.route.as_mut().unwrap().kind = "external_data_blocker".to_string();
        state.route.as_mut().unwrap().acceptance_kind =
            Some(RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged);

        let command = pending_command(target.path(), &state).unwrap();
        assert!(
            command
                .argv
                .iter()
                .any(|arg| arg == "resume-replay-planning")
        );
        let action = resume_replay_planning(target.path(), &mut state, "repair-current").unwrap();

        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert!(state.route.is_none());
        assert!(state.target_fingerprint.is_none());
        assert!(matches!(
            action.action,
            super::super::model::RewriteAction::AdvanceRequired { .. }
        ));
    }

    #[test]
    fn administrator_can_cancel_a_misrouted_source_change_repair() {
        let target = tempfile::tempdir().unwrap();
        let mut state = repair_state("source-revision".to_string());
        state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Comparison;
        state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
        state.route.as_mut().unwrap().kind = "source_change".to_string();
        state.route.as_mut().unwrap().acceptance_kind =
            Some(RewriteRepairAcceptanceKind::SourceRevisionChanged);
        let revision = state.revision;

        let action = cancel_misroute(
            target.path(),
            &mut state,
            "repair-current",
            "comparison evidence was misclassified",
        )
        .unwrap();

        assert_eq!(state.phase, RewritePhase::ImplementationRequired);
        assert_eq!(
            state.active_issue.as_ref().map(|issue| issue.owner),
            Some(RewriteIssueOwner::TargetCode)
        );
        assert!(state.route.is_none());
        assert_eq!(state.revision, revision + 1);
        assert!(matches!(
            action.action,
            super::super::model::RewriteAction::AdvanceRequired { .. }
        ));
    }

    #[test]
    fn administrator_can_cancel_a_misrouted_capability_repair() {
        let target = tempfile::tempdir().unwrap();
        for (route_kind, issue_kind) in [
            ("replay_capability_gap", RewriteIssueKind::Replay),
            ("replay_capability_gap", RewriteIssueKind::Dependency),
            ("recorder_capability_gap", RewriteIssueKind::Response),
            ("recorder_capability_gap", RewriteIssueKind::Dependency),
        ] {
            let mut state = repair_state("traffic-e2e-revision".to_string());
            state.active_issue.as_mut().unwrap().kind = issue_kind;
            state.route.as_mut().unwrap().kind = route_kind.to_string();
            let revision = state.revision;

            let action = cancel_misroute(
                target.path(),
                &mut state,
                "repair-current",
                "target behavior caused the observed mismatch",
            )
            .unwrap();

            assert_eq!(state.phase, RewritePhase::ImplementationRequired);
            assert_eq!(
                state.active_issue.as_ref().map(|issue| issue.owner),
                Some(RewriteIssueOwner::TargetCode)
            );
            assert!(state.route.is_none());
            assert_eq!(state.revision, revision + 1);
            assert!(matches!(
                action.action,
                super::super::model::RewriteAction::AdvanceRequired { .. }
            ));
        }
    }

    #[test]
    fn repair_cancellation_rejects_wrong_id_incompatible_issue_and_external_data_routes() {
        let target = tempfile::tempdir().unwrap();
        let mut state = repair_state("revision".to_string());

        assert!(cancel_misroute(target.path(), &mut state, "repair-stale", "misroute").is_err());

        state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
        assert!(cancel_misroute(target.path(), &mut state, "repair-current", "misroute").is_err());

        state.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::SourceInvestigation;
        state.route.as_mut().unwrap().kind = "external_data_blocker".to_string();
        state.route.as_mut().unwrap().acceptance_kind =
            Some(RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged);
        assert!(cancel_misroute(target.path(), &mut state, "repair-current", "misroute").is_err());
        assert_eq!(state.phase, RewritePhase::SystemRepairRequired);
        assert!(state.route.is_some());
    }

    #[test]
    fn administrator_can_rearm_replay_after_a_matching_out_of_band_run() {
        let target = committed_target();
        let target_fingerprint = fingerprint::repository_fingerprint(target.path()).unwrap();
        let mut state = out_of_band_retry_state(&target_fingerprint);
        let options = retry_options();
        let observed = crate::e2e_run::E2eFocusedAttemptSummary {
            attempt: 13,
            passed: true,
            case_source: PathBuf::from("/cases"),
            case_inventory_id: "inventory".to_string(),
        };

        let action =
            retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &observed)
                .unwrap();

        assert!(state.target_fingerprint.is_none());
        assert!(!state.e2e_current);
        assert!(!state.comparison_current);
        assert!(matches!(
            action.action,
            super::super::model::RewriteAction::AdvanceRequired { .. }
        ));
    }

    #[test]
    fn replay_retry_rejects_a_changed_target_or_nonpassing_external_attempt() {
        let target = committed_target();
        let target_fingerprint = fingerprint::repository_fingerprint(target.path()).unwrap();
        let options = retry_options();
        let mut state = out_of_band_retry_state(&target_fingerprint);
        let nonpassing = crate::e2e_run::E2eFocusedAttemptSummary {
            attempt: 13,
            passed: false,
            case_source: PathBuf::from("/cases"),
            case_inventory_id: "inventory".to_string(),
        };
        assert!(
            retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &nonpassing)
                .is_err()
        );

        let mut state = out_of_band_retry_state(&target_fingerprint);
        fs::write(target.path().join("src.rs"), "fn changed() {}\n").unwrap();
        let passing = crate::e2e_run::E2eFocusedAttemptSummary {
            passed: true,
            ..nonpassing
        };
        assert!(
            retry_replay_after_out_of_band_run(target.path(), &mut state, &options, &passing)
                .is_err()
        );
    }

    fn repair_state(observed_revision: String) -> RewriteState {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::SystemRepairRequired;
        state.active_issue = Some(RewriteIssue {
            id: "issue-replay".to_string(),
            kind: RewriteIssueKind::Replay,
            owner: RewriteIssueOwner::TrafficE2eSystem,
            summary: "replay capability gap".to_string(),
            pointer_pattern: None,
            representative: None,
            response_diagnosis: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: "target".to_string(),
            attempt: 1,
            comparison_observation: None,
        });
        state.route = Some(RewriteRouteRecord {
            kind: "replay_capability_gap".to_string(),
            evidence_id: "evidence-replay".to_string(),
            source_ref: "src/replay.rs:1".to_string(),
            required_change: "support the recorded exchange".to_string(),
            repair_id: Some("repair-current".to_string()),
            acceptance_kind: Some(RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged),
            observed_revision: Some(observed_revision),
            legacy_acceptance_command: None,
        });
        state
    }

    fn out_of_band_retry_state(target_fingerprint: &str) -> RewriteState {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.api = "MOTAN /rpc/example".to_string();
        state.case_source = Some(PathBuf::from("/cases"));
        state.case_inventory_id = Some("inventory".to_string());
        state.target_fingerprint = Some(target_fingerprint.to_string());
        state.attempts.push(RewriteAttemptSummary {
            attempt: 12,
            passed: false,
            gates: E2eVerificationGates {
                responses: E2eResponseGate::Nonpassing,
                replay: E2eReplayGate::Complete,
                dependencies: E2eDependencyGate::Clean,
            },
            counts: E2eDiagnosisCounts {
                selected: 10,
                executed: 10,
                response_passed: 0,
                response_nonpassing: 10,
                response_incomplete: 0,
            },
        });
        state.active_issue = Some(RewriteIssue {
            id: "issue-response".to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "response assertion could not be evaluated".to_string(),
            pointer_pattern: Some("$response".to_string()),
            representative: None,
            response_diagnosis: None,
            possible_causes: vec!["response_assertion_evaluation_or_evidence_failure".to_string()],
            observed_target_fingerprint: target_fingerprint.to_string(),
            attempt: 12,
            comparison_observation: None,
        });
        state
    }

    fn retry_options() -> RewriteReplayRetryOptions {
        RewriteReplayRetryOptions {
            target_root: PathBuf::from("/target"),
            api: "MOTAN /rpc/example".to_string(),
            failed_attempt: 12,
            out_of_band_attempt: 13,
            reason: "focused Replay was run outside the coordinator".to_string(),
            confirm_out_of_band_run: true,
        }
    }

    fn committed_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        git_ok(target.path(), &["init", "-q"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-q", "-m", "baseline"]);
        target
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(repository)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
}
