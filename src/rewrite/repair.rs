use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteActionEnvelope, RewriteCommandSpec, RewriteIssue, RewriteIssueKind, RewriteIssueOwner,
    RewritePhase, RewriteRecordingReason, RewriteRepairAcceptanceKind, RewriteRouteRecord,
    RewriteRouteReport, RewriteState,
};
use super::store::RewriteStore;
use super::{action, artifacts, evidence, fingerprint, inventory, recording};
use crate::{ManagedRecordingOperation, RecordingApi, RewriteContext};

#[derive(Debug, Clone)]
pub struct RewriteRouteOptions {
    pub target_root: PathBuf,
    pub kind: String,
    pub evidence_id: String,
    pub source_ref: String,
    pub required_change: String,
}

pub(super) fn route(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRouteOptions,
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
            crate::platform::source_revision(target_root)
        }
        RewriteRepairAcceptanceKind::SourceRuntimeInputsChanged => {
            fingerprint::source_runtime_inputs_revision(target_root)
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
    use super::*;
    use crate::rewrite::model::{RewriteIssueOwner, RewritePhase};

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
}
