use std::path::Path;

use anyhow::Result;

use crate::RecordingApi;

use super::model::{
    ACTION_SCHEMA_VERSION, RewriteAction, RewriteActionEnvelope, RewriteCommandSpec,
    RewriteFocusedE2eExecution, RewriteFocusedE2eExecutionMode, RewriteInputRequiredReason,
    RewritePhase, RewriteRecordingInputMode, RewriteState, RewriteWorkflowView,
};
use super::{evidence, fingerprint, inventory, recording_action};

pub(super) fn for_state(target_root: &Path, state: &RewriteState) -> RewriteActionEnvelope {
    envelope(state, state_action(target_root, state))
}

pub(super) fn for_status(
    target_root: &Path,
    state: &RewriteState,
) -> Result<RewriteActionEnvelope> {
    let recording_status = recording_action::status_action(target_root, state)?;
    let action = match state.phase {
        RewritePhase::RecordingRequired | RewritePhase::ComparisonRecordingRequired
            if recording_status.is_some() =>
        {
            recording_status.expect("recording status was checked")
        }
        RewritePhase::ImplementationRequired
            if state.target_fingerprint.as_deref()
                != Some(fingerprint::repository_fingerprint(target_root)?.as_str()) =>
        {
            resume_required(
                target_root,
                "target repository changed after the latest focused attempt; resume coordinator verification"
                    .to_string(),
            )
        }
        _ => state_action(target_root, state),
    };
    Ok(envelope(state, action))
}

fn envelope(state: &RewriteState, action: RewriteAction) -> RewriteActionEnvelope {
    let workflow = Some(workflow_view(state));
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow,
        api_inventory: Some(inventory::view(state)),
        latest_focused_e2e: latest_focused_e2e(state),
        terminal_allowed: state.phase == RewritePhase::SliceComplete,
        action,
    }
}

fn state_action(target_root: &Path, state: &RewriteState) -> RewriteAction {
    if state.phase == RewritePhase::SystemRepairRequired
        && state
            .route
            .as_ref()
            .is_some_and(|route| route.repair_id.is_none())
    {
        return resume_required(
            target_root,
            "initialize coordinator-issued acceptance for the pending legacy system repair"
                .to_string(),
        );
    }
    if state.phase == RewritePhase::ApiPending && inventory::current_requires_source_route(state) {
        return RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {} requires a route confirmed from source registration",
                state.api
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
        };
    }
    if state.phase == RewritePhase::ImplementationRequired {
        if let Some(plan) = &state.rule_plan {
            return RewriteAction::PlanApplyRequired {
                summary: "apply the unchanged pending response-rule plan".to_string(),
                command: rule_apply_command(target_root, &plan.id),
            };
        }
        if let Some(plan) = &state.dependency_rule_plan {
            if plan.reused_existing {
                return resume_required_with_command(
                    format!(
                        "background-dependency selector is already covered by rule {}; skip apply and refresh standard recording evidence",
                        plan.effective_name.as_deref().unwrap_or(&plan.name)
                    ),
                    super::dependency_rule::fresh_recording_request(target_root, state),
                );
            }
            return RewriteAction::PlanApplyRequired {
                summary: "apply the unchanged pending background-dependency plan".to_string(),
                command: dependency_rule_apply_command(target_root, &plan.id),
            };
        }
    }
    match state.phase {
        RewritePhase::RecordingRequired => RewriteAction::RecordingRequired {
            summary: recording_summary(state),
            input_mode: if state.recording_input_case_source.is_some() {
                RewriteRecordingInputMode::ReusedAtomicRecording
            } else {
                RewriteRecordingInputMode::ExternalLiveTraffic
            },
            recording_input_diagnosis: if state.recording_input_case_source.is_none() {
                state.recording_input_diagnosis.clone()
            } else {
                None
            },
            command: recording_action::command(target_root, state, false),
            resume: next_command(target_root),
        },
        RewritePhase::ApiPending => resume_required(
            target_root,
            format!("continue with the next recorded API {}", state.api),
        ),
        RewritePhase::ImplementationRequired => RewriteAction::ImplementationRequired {
            issue: state
                .active_issue
                .clone()
                .expect("implementation phase requires an issue"),
            evidence_commands: evidence::commands(target_root, state),
            acceptance: next_command(target_root),
        },
        RewritePhase::ComparisonRecordingRequired => RewriteAction::ComparisonRecordingRequired {
            summary: state.comparison_rejection.as_ref().map_or_else(
                || format!("generate fresh comparison evidence for {}", state.api),
                |reason| {
                    format!(
                        "previous comparison recording was rejected ({reason}); generate fresh comparison evidence for {}",
                        state.api
                    )
                },
            ),
            command: recording_action::command(target_root, state, true),
            resume: next_command(target_root),
        },
        RewritePhase::SystemRepairRequired => RewriteAction::SystemRepairRequired {
            issue: state
                .active_issue
                .clone()
                .expect("system repair phase requires an issue"),
            route: state.route.clone(),
            acceptance: state.route.as_ref().and_then(|route| {
                route
                    .repair_id
                    .as_deref()
                    .map(|repair_id| repair_verify_command(target_root, repair_id))
            }),
        },
        RewritePhase::SliceComplete => RewriteAction::Complete {
            summary: format!(
                "all {} recorded API slice(s) have current E2E and comparison evidence",
                state.api_inventory.len()
            ),
            e2e_current: state.e2e_current,
            comparison_current: state.comparison_current,
        },
    }
}

fn resume_required(target_root: &Path, summary: String) -> RewriteAction {
    resume_required_with_command(summary, next_command(target_root))
}

fn resume_required_with_command(summary: String, command: RewriteCommandSpec) -> RewriteAction {
    RewriteAction::ResumeRequired { summary, command }
}

pub(super) fn resume_envelope(
    target_root: &Path,
    state: &RewriteState,
    summary: String,
) -> RewriteActionEnvelope {
    envelope(state, resume_required(target_root, summary))
}

fn recording_summary(state: &RewriteState) -> String {
    let summary = if let Some(reason) = &state.recording_rejection {
        format!(
            "previous standard recording was rejected ({reason}); generate a replacement for {}",
            workflow_scope(state)
        )
    } else {
        match state.recording_request_reason {
            Some(reason) => format!(
                "fresh standard recording requested ({reason}) for {}",
                workflow_scope(state)
            ),
            None => format!(
                "generate one finalized standard recording for {}",
                workflow_scope(state)
            ),
        }
    };
    if state.recording_input_case_source.is_none() {
        format!(
            "{summary}; no exact-scope atomic historical input is reusable, capture fresh external live traffic"
        )
    } else {
        summary
    }
}

pub(super) fn input_required(_target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::WorkflowNotInitialized,
            summary: "start the rewrite workflow for every API observed through recorder configuration, or optionally select one API".to_string(),
            required: vec!["run `traffic-e2e rewrite next`; optional: --api 'METHOD /path-or-pattern'".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn source_route_required(
    _target_root: &Path,
    api: &RecordingApi,
) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::SourceRouteRequired,
            summary: format!(
                "dynamic API {api} requires a route confirmed from source registration"
            ),
            required: vec!["--source-route <confirmed-source-route>".to_string()],
        },
        terminal_allowed: false,
    }
}

pub(super) fn recovery_required(target_root: &Path) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: ACTION_SCHEMA_VERSION,
        workflow: None,
        api_inventory: None,
        latest_focused_e2e: None,
        action: RewriteAction::RecoveryRequired {
            summary: "rewrite workflow is locked; execute the recovery command before retrying"
                .to_string(),
            command: recover_command(target_root),
            resume: next_command(target_root),
        },
        terminal_allowed: false,
    }
}

pub(super) fn latest_focused_e2e(state: &RewriteState) -> Option<RewriteFocusedE2eExecution> {
    let current = state.attempts.last()?;
    let case_source = state.case_source.clone()?;
    let previous_attempt = state
        .attempts
        .iter()
        .rev()
        .nth(1)
        .map(|attempt| attempt.attempt);
    Some(RewriteFocusedE2eExecution {
        execution_mode: if previous_attempt.is_some() {
            RewriteFocusedE2eExecutionMode::ReusedStandardCases
        } else {
            RewriteFocusedE2eExecutionMode::FreshStandardCases
        },
        recording_run_id: state.recording_run_id.clone(),
        case_source,
        case_inventory_id: state.case_inventory_id.clone(),
        previous_attempt,
        current_attempt: current.attempt,
        passed: current.passed,
    })
}

pub(super) fn workflow_view(state: &RewriteState) -> RewriteWorkflowView {
    RewriteWorkflowView {
        id: state.workflow_id.clone(),
        revision: state.revision,
        phase: state.phase,
        scope: workflow_scope(state),
    }
}

fn workflow_scope(state: &RewriteState) -> String {
    let scope = inventory::recording_scope(state);
    if scope.is_empty() {
        "all_configured_apis".to_string()
    } else {
        scope.join(", ")
    }
}

pub(super) fn command(
    target_root: &Path,
    argv: Vec<String>,
    required_env_names: Vec<String>,
) -> RewriteCommandSpec {
    RewriteCommandSpec {
        cwd: target_root.to_path_buf(),
        argv,
        required_env_names,
    }
}

pub(super) fn next_command(target_root: &Path) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "next".to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn status_command(target_root: &Path) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "status".to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn rule_apply_command(target_root: &Path, plan_id: &str) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "rule".to_string(),
            "apply".to_string(),
            plan_id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn dependency_rule_apply_command(
    target_root: &Path,
    plan_id: &str,
) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "dependency-rule".to_string(),
            "apply".to_string(),
            plan_id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn repair_verify_command(target_root: &Path, repair_id: &str) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "repair".to_string(),
            "verify".to_string(),
            repair_id.to_string(),
        ],
        Vec::new(),
    )
}

pub(super) fn recover_command(target_root: &Path) -> RewriteCommandSpec {
    command(
        target_root,
        vec![
            "traffic-e2e".to_string(),
            "rewrite".to_string(),
            "recover".to_string(),
        ],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::super::recording_action::recording_action_id;
    use super::super::{artifacts, recording_execution};
    use super::*;
    use crate::{
        E2eDependencyGate, E2eDiagnosisCounts, E2eReplayGate, E2eResponseGate, E2eVerificationGates,
    };

    use super::super::model::{
        RewriteAttemptSummary, RewriteDependencyRulePlanRecord, RewriteDependencyRuleSpec,
        RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteRepairAcceptanceKind,
        RewriteRouteRecord, RewriteRulePlanRecord,
    };

    #[test]
    fn status_recovers_the_exact_recording_action_until_a_result_exists() {
        let target = tempfile::tempdir().unwrap();
        let mut state = crate::rewrite::test_state();

        let pending = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            pending.pointer("/action/kind"),
            Some(&serde_json::json!("recording_required"))
        );
        assert_eq!(
            pending.pointer("/action/command/cwd"),
            Some(&serde_json::json!(target.path()))
        );
        assert!(
            pending
                .pointer("/action/command/argv/4")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.starts_with("recording-"))
        );

        let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            manifest,
            br#"{"status":"completed","recording_apis":["GET /api"],"published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        let resumable = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            resumable.pointer("/action/kind"),
            Some(&serde_json::json!("resume_required"))
        );
        assert_eq!(
            resumable.pointer("/action/command/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "next"]))
        );

        state.phase = RewritePhase::ComparisonRecordingRequired;
        state.comparison_run_id = Some("20260802000001".to_string());
        let comparison_pending =
            serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            comparison_pending.pointer("/action/kind"),
            Some(&serde_json::json!("comparison_recording_required"))
        );
        assert_eq!(
            comparison_pending.pointer("/action/command/argv/4"),
            Some(&serde_json::json!(recording_action_id(&state, true)))
        );

        let comparison_manifest = artifacts::comparison_manifest(target.path(), "20260802000001");
        fs::create_dir_all(comparison_manifest.parent().unwrap()).unwrap();
        fs::write(
            comparison_manifest,
            br#"{"status":"completed","ready":true,"recording_apis":["GET /api"],"counts":{"published":1,"failed":0},"errors":[]}"#,
        )
        .unwrap();
        let comparison_resumable =
            serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            comparison_resumable.pointer("/action/kind"),
            Some(&serde_json::json!("resume_required"))
        );
    }

    #[test]
    fn status_requires_recovery_for_an_unowned_running_manifest() {
        let target = tempfile::tempdir().unwrap();
        let state = crate::rewrite::test_state();
        let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            manifest,
            br#"{"status":"running","recording_apis":["GET /api"],"published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();

        let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            status.pointer("/action/kind"),
            Some(&serde_json::json!("recovery_required"))
        );
        assert_eq!(
            status.pointer("/action/command/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "recover"]))
        );
    }

    #[test]
    fn status_reports_a_live_recording_without_returning_execute_again() {
        let target = tempfile::tempdir().unwrap();
        let state = crate::rewrite::test_state();
        let manifest = artifacts::recording_manifest(target.path(), &state.recording_run_id);
        fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        fs::write(
            manifest,
            br#"{"status":"running","recording_apis":["GET /api"],"published_cases":1,"failed_cases":0,"errors":[]}"#,
        )
        .unwrap();
        recording_execution::publish(
            target.path(),
            &recording_execution::RecordingExecutionMarker {
                action_id: recording_action_id(&state, false),
                run_id: state.recording_run_id.clone(),
                operation: "record".to_string(),
                pid: std::process::id(),
            },
        )
        .unwrap();

        let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            status.pointer("/action/kind"),
            Some(&serde_json::json!("recording_in_progress"))
        );
        assert_eq!(
            status.pointer("/action/status/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "status"]))
        );
        assert!(status.pointer("/action/command").is_none());
    }

    #[test]
    fn recording_action_id_is_stable_and_bound_to_the_request_corpus() {
        let mut state = crate::rewrite::test_state();
        let original = recording_action_id(&state, false);

        state.bump();
        assert_eq!(recording_action_id(&state, false), original);

        state.recording_input_case_source = Some(PathBuf::from("another-recording"));
        assert_ne!(recording_action_id(&state, false), original);
    }

    #[test]
    fn status_returns_the_coordinator_issued_repair_acceptance() {
        let target = tempfile::tempdir().unwrap();
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::SystemRepairRequired;
        state.active_issue = Some(RewriteIssue {
            id: "issue-replay".to_string(),
            kind: RewriteIssueKind::Replay,
            owner: RewriteIssueOwner::TrafficE2eSystem,
            summary: "replay capability gap".to_string(),
            pointer_pattern: None,
            representative: None,
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
            observed_revision: Some("fnv1a64:old".to_string()),
            legacy_acceptance_command: None,
        });

        let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();

        assert_eq!(
            status.pointer("/action/acceptance/argv"),
            Some(&serde_json::json!([
                "traffic-e2e",
                "rewrite",
                "repair",
                "verify",
                "repair-current"
            ]))
        );
        assert_eq!(
            status.pointer("/action/acceptance/cwd"),
            Some(&serde_json::json!(target.path()))
        );
    }

    #[test]
    fn pending_rule_plans_are_recoverable_by_plan_id() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.rule_plan = Some(RewriteRulePlanRecord {
            id: "plan-response".to_string(),
            issue_id: "issue-response".to_string(),
            kind: "dynamic".to_string(),
            json_pointer: "/request_id".to_string(),
            dynamic_mechanisms: vec!["uuid".to_string()],
            source_evidence: Some("src/id.rs:new".to_string()),
            source_example: None,
            target_example: None,
            evidence_id: "evidence-response".to_string(),
        });

        let target = Path::new("/target");
        let response = serde_json::to_value(for_state(target, &state)).unwrap();
        assert_eq!(
            response.pointer("/action/kind"),
            Some(&serde_json::json!("plan_apply_required"))
        );
        assert_eq!(
            response.pointer("/action/command/argv"),
            Some(&serde_json::json!([
                "traffic-e2e",
                "rewrite",
                "rule",
                "apply",
                "plan-response"
            ]))
        );

        state.rule_plan = None;
        state.dependency_rule_plan = Some(RewriteDependencyRulePlanRecord {
            id: "plan-dependency".to_string(),
            issue_id: "issue-dependency".to_string(),
            evidence_id: "evidence-dependency".to_string(),
            name: "cache-warm".to_string(),
            source_evidence: "src/cache.rs:warm".to_string(),
            spec: RewriteDependencyRuleSpec::Http {
                authority: "config.internal".to_string(),
                method: "GET".to_string(),
                path_prefix: "/config".to_string(),
            },
            reused_existing: false,
            effective_name: None,
        });
        let dependency = serde_json::to_value(for_state(target, &state)).unwrap();
        assert_eq!(
            dependency.pointer("/action/command/argv"),
            Some(&serde_json::json!([
                "traffic-e2e",
                "rewrite",
                "dependency-rule",
                "apply",
                "plan-dependency"
            ]))
        );

        let plan = state.dependency_rule_plan.as_mut().unwrap();
        plan.reused_existing = true;
        plan.effective_name = Some("existing-cache-warm".to_string());
        let reused = serde_json::to_value(for_state(target, &state)).unwrap();
        assert_eq!(
            reused.pointer("/action/kind"),
            Some(&serde_json::json!("resume_required"))
        );
        assert_eq!(
            reused.pointer("/action/command/argv/3"),
            Some(&serde_json::json!("request"))
        );
        assert!(
            reused
                .pointer("/action/summary")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|summary| summary.contains("existing-cache-warm"))
        );
    }

    #[test]
    fn status_requests_resume_after_the_target_changes() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join("src")).unwrap();
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        git_ok(target.path(), &["init"]);
        git_ok(target.path(), &["config", "user.email", "test@example.com"]);
        git_ok(target.path(), &["config", "user.name", "Traffic E2E Test"]);
        git_ok(target.path(), &["add", "."]);
        git_ok(target.path(), &["commit", "-m", "baseline"]);

        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();

        let status = serde_json::to_value(for_status(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            status.pointer("/action/kind"),
            Some(&serde_json::json!("resume_required"))
        );
        assert_eq!(
            status.pointer("/action/command/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "next"]))
        );
    }

    #[test]
    fn identifies_fresh_and_reused_standard_cases() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::SliceComplete;
        state.case_source = Some(PathBuf::from(
            ".traffic-e2e/artifacts/recordings/20260802000000",
        ));
        state.case_inventory_id = Some("fnv1a64:case-inventory".to_string());
        state.attempts.push(test_attempt(4, false));

        let target = Path::new("/target");
        let fresh = serde_json::to_value(for_state(target, &state)).unwrap();
        assert_eq!(
            fresh.pointer("/latest_focused_e2e/execution_mode"),
            Some(&serde_json::json!("fresh_standard_cases"))
        );
        assert_eq!(
            fresh.pointer("/latest_focused_e2e/recording_run_id"),
            Some(&serde_json::json!("20260802000000"))
        );
        assert_eq!(
            fresh.pointer("/latest_focused_e2e/case_inventory_id"),
            Some(&serde_json::json!("fnv1a64:case-inventory"))
        );
        assert!(
            fresh
                .pointer("/latest_focused_e2e/previous_attempt")
                .is_none()
        );
        assert_eq!(
            fresh.pointer("/latest_focused_e2e/current_attempt"),
            Some(&serde_json::json!(4))
        );

        state.attempts.push(test_attempt(5, true));
        let reused = serde_json::to_value(for_state(target, &state)).unwrap();
        assert_eq!(
            reused.pointer("/latest_focused_e2e/execution_mode"),
            Some(&serde_json::json!("reused_standard_cases"))
        );
        assert_eq!(
            reused.pointer("/latest_focused_e2e/previous_attempt"),
            Some(&serde_json::json!(4))
        );
        assert_eq!(
            reused.pointer("/latest_focused_e2e/current_attempt"),
            Some(&serde_json::json!(5))
        );
        assert_eq!(
            reused.pointer("/latest_focused_e2e/passed"),
            Some(&serde_json::json!(true))
        );
    }

    fn test_attempt(attempt: u64, passed: bool) -> RewriteAttemptSummary {
        RewriteAttemptSummary {
            attempt,
            passed,
            gates: E2eVerificationGates {
                responses: if passed {
                    E2eResponseGate::Passed
                } else {
                    E2eResponseGate::Nonpassing
                },
                replay: E2eReplayGate::Complete,
                dependencies: E2eDependencyGate::Clean,
            },
            counts: E2eDiagnosisCounts {
                selected: 1,
                executed: 1,
                response_passed: usize::from(passed),
                response_nonpassing: usize::from(!passed),
                response_incomplete: 0,
            },
        }
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }
}
