mod action;
mod artifacts;
mod evidence;
mod fingerprint;
mod issue;
mod model;
mod recording;
mod rule;
mod store;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub use model::{
    RewriteAction, RewriteActionEnvelope, RewriteCommandSpec, RewriteEvidenceCommand,
    RewriteEvidenceReport, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewritePhase,
    RewriteRecordingKind, RewriteRecordingReason, RewriteRecoveryReport, RewriteRouteReport,
    RewriteRuleReport, RewriteStatusReport, RewriteWorkflowView,
};
pub use recording::{RewriteRecordingRequestOptions, request_rewrite_recording};
pub use rule::RewriteRulePlanOptions;

use model::{
    RewriteAttemptDelta, RewriteAttemptSummary, RewriteRecordingSettings, RewriteRouteRecord,
    RewriteState, STATE_VERSION,
};
use store::RewriteStore;

use crate::{
    ComparisonVerificationOptions, E2eRunContext, E2eRunPrepareOptions, ManagedRecordingOperation,
    RecordingApi, prepare_e2e_run, resolve_recording_api_member, run_e2e_api,
    update_comparison_progress, verify_comparison_recording,
};

#[derive(Debug, Clone)]
pub struct RewriteNextOptions {
    pub target_root: PathBuf,
    pub api: Option<RecordingApi>,
    pub source_route: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewriteContext {
    pub target_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RewriteRouteOptions {
    pub target_root: PathBuf,
    pub kind: String,
    pub evidence_id: String,
    pub source_ref: String,
    pub required_change: String,
    pub acceptance_command: String,
}

pub async fn next_rewrite(options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let Some(_lock) = store.try_lock()? else {
        return Ok(action::recovery_required());
    };
    let mut state = match store.load()? {
        Some(state) => {
            if let Some(api) = &options.api {
                ensure!(
                    state.api == api.to_string(),
                    "active rewrite scope is {}; refusing a different --api",
                    state.api
                );
            }
            if let Some(route) = &options.source_route {
                ensure!(
                    state.source_route == *route,
                    "active rewrite source route is {:?}; refusing a different --source-route",
                    state.source_route
                );
            }
            state
        }
        None => {
            let Some(api) = options.api else {
                return Ok(action::input_required());
            };
            let source_route = match options.source_route {
                Some(route) => route,
                None if !api.is_dynamic() => api.path_pattern().to_string(),
                None => return Ok(action::source_route_required(&api)),
            };
            validate_single_line("source route", &source_route)?;
            let recording_run_id =
                artifacts::allocate_run_id(&target_root, ManagedRecordingOperation::Record)?;
            let state = RewriteState {
                version: STATE_VERSION,
                revision: 1,
                workflow_id: format!("rewrite-{}", uuid::Uuid::new_v4().simple()),
                phase: RewritePhase::RecordingRequired,
                api: api.to_string(),
                source_route,
                recording_run_id,
                recording_rejection: None,
                recording_settings: RewriteRecordingSettings::default(),
                recording_request_reason: None,
                comparison_run_id: None,
                comparison_rejection: None,
                case_source: None,
                source_revision: None,
                group_id: None,
                target_fingerprint: None,
                attempts: Vec::new(),
                attempt_delta: None,
                active_issue: None,
                rule_plan: None,
                route: None,
                e2e_current: false,
                comparison_current: false,
            };
            store.save(&state)?;
            state
        }
    };

    match state.phase {
        RewritePhase::RecordingRequired => {
            if !artifacts::recording_manifest(&target_root, &state.recording_run_id).is_file() {
                return Ok(action::for_state(&state));
            }
            if let Err(error) = artifacts::validate_standard_recording(&target_root, &state) {
                state.recording_rejection = Some(artifacts::recording_rejection(&error));
                state.recording_run_id =
                    artifacts::allocate_run_id(&target_root, ManagedRecordingOperation::Record)?;
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&state));
            }
            state.recording_rejection = None;
            prepare_recording(&target_root, &mut state)?;
            store.save(&state)?;
            run_and_transition(&target_root, &mut state).await?;
            store.save(&state)?;
            Ok(action::for_state(&state))
        }
        RewritePhase::ImplementationRequired => {
            let current = fingerprint::repository_fingerprint(&target_root)?;
            if state.target_fingerprint.as_deref() == Some(current.as_str()) {
                return Ok(action::for_state(&state));
            }
            state.e2e_current = false;
            state.comparison_current = false;
            run_and_transition(&target_root, &mut state).await?;
            store.save(&state)?;
            Ok(action::for_state(&state))
        }
        RewritePhase::ComparisonRecordingRequired => {
            let run_id = state
                .comparison_run_id
                .as_deref()
                .context("comparison phase has no allocated run id")?;
            if !artifacts::comparison_manifest(&target_root, run_id).is_file() {
                return Ok(action::for_state(&state));
            }
            if let Err(error) = artifacts::validate_comparison_recording(&target_root, &state) {
                state.comparison_rejection = Some(artifacts::comparison_rejection(&error));
                state.comparison_run_id = Some(artifacts::allocate_run_id(
                    &target_root,
                    ManagedRecordingOperation::RecordComparison,
                )?);
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&state));
            }
            state.comparison_rejection = None;
            compare_and_transition(&target_root, &mut state)?;
            store.save(&state)?;
            Ok(action::for_state(&state))
        }
        RewritePhase::SystemRepairRequired | RewritePhase::SliceComplete => {
            Ok(action::for_state(&state))
        }
    }
}

pub fn status_rewrite(context: RewriteContext) -> Result<RewriteStatusReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?.load()?;
    let next = action::next_command();
    Ok(match state {
        Some(state) => RewriteStatusReport {
            initialized: true,
            workflow: Some(action::workflow_view(&state)),
            active_issue: state.active_issue.clone(),
            e2e_current: state.e2e_current,
            comparison_current: state.comparison_current,
            terminal_allowed: state.phase == RewritePhase::SliceComplete,
            next,
        },
        None => RewriteStatusReport {
            initialized: false,
            workflow: None,
            active_issue: None,
            e2e_current: false,
            comparison_current: false,
            terminal_allowed: false,
            next,
        },
    })
}

pub fn query_rewrite_evidence(
    context: RewriteContext,
    query_id: &str,
) -> Result<RewriteEvidenceReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let state = RewriteStore::new(&target_root)?
        .load()?
        .context("rewrite workflow has not been initialized")?;
    evidence::query(&target_root, &state, query_id)
}

pub fn plan_rewrite_rule(
    context: RewriteContext,
    options: RewriteRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let report = rule::plan(&target_root, &mut state, options)?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_rule(context: RewriteContext, plan_id: &str) -> Result<RewriteRuleReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let report = rule::apply(&target_root, &mut state, plan_id)?;
    state.target_fingerprint = None;
    store.save(&state)?;
    Ok(report)
}

pub fn route_rewrite(options: RewriteRouteOptions) -> Result<RewriteRouteReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let mut issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    validate_single_line("route source reference", &options.source_ref)?;
    validate_single_line("required system change", &options.required_change)?;
    validate_single_line("acceptance command", &options.acceptance_command)?;
    validate_route_kind(&issue, &options.kind)?;
    let valid_evidence = evidence::commands(&state).into_iter().any(|command| {
        evidence::query(&target_root, &state, &command.query_id)
            .is_ok_and(|report| report.evidence_id == options.evidence_id)
    });
    ensure!(
        valid_evidence,
        "route evidence is stale or belongs to another issue"
    );
    let route = RewriteRouteRecord {
        kind: options.kind,
        evidence_id: options.evidence_id,
        source_ref: options.source_ref,
        required_change: options.required_change,
        acceptance_command: options.acceptance_command,
    };
    issue.owner = match route.kind.as_str() {
        "recorder_capability_gap" | "replay_capability_gap" => RewriteIssueOwner::TrafficE2eSystem,
        _ => RewriteIssueOwner::SourceInvestigation,
    };
    state.active_issue = Some(issue.clone());
    state.route = Some(route.clone());
    state.phase = RewritePhase::SystemRepairRequired;
    state.bump();
    store.save(&state)?;
    Ok(RewriteRouteReport {
        accepted: true,
        issue_id: issue.id,
        route,
        next_command: action::next_command(),
    })
}

pub async fn recover_rewrite(context: RewriteContext) -> Result<RewriteRecoveryReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let recovered_stale_lock = store.recover_lock()?;
    let _lock = store.lock()?;
    let recovered_focused_attempt = match store.load()? {
        Some(state) => match (state.case_source, state.group_id) {
            (Some(case_source), Some(group_id)) => {
                crate::e2e_run::recover_focused_e2e_api(
                    E2eRunContext {
                        target_root,
                        case_source,
                        run_key: None,
                    },
                    &group_id,
                )
                .await?
            }
            _ => false,
        },
        None => false,
    };
    Ok(RewriteRecoveryReport {
        recovered_stale_lock,
        recovered_focused_attempt,
        next: action::next_command(),
    })
}

fn prepare_recording(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let case_source = artifacts::recording_run(target_root, &state.recording_run_id);
    let api = state.api.parse::<RecordingApi>()?;
    let member = resolve_recording_api_member(&case_source, &api)?;
    let source_revision = fingerprint::source_container_revision(&project.source_container)?;
    let prepared = prepare_e2e_run(E2eRunPrepareOptions {
        context: E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source: case_source.clone(),
            run_key: None,
        },
        case_dir: member,
        method: api.method().to_string(),
        source_route: state.source_route.clone(),
        pattern: api.is_dynamic().then(|| api.path_pattern().to_string()),
        source_revision: source_revision.clone(),
    })?;
    ensure!(
        prepared.ready_for_full_run,
        "the selected recording contains cases outside the active API scope"
    );
    state.case_source = Some(case_source);
    state.source_revision = Some(source_revision);
    state.group_id = Some(prepared.group.group_id);
    state.bump();
    Ok(())
}

async fn run_and_transition(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no case source")?;
    let api = state
        .group_id
        .clone()
        .context("rewrite workflow has no prepared API group")?;
    let result = run_e2e_api(
        E2eRunContext {
            target_root: target_root.to_path_buf(),
            case_source,
            run_key: None,
        },
        &api,
    )
    .await?;
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let summary = RewriteAttemptSummary {
        attempt: result.attempt,
        passed: result.passed,
        gates: result.gates.clone(),
        counts: result.diagnosis.counts.clone(),
    };
    state.attempt_delta = state
        .attempts
        .last()
        .map(|previous| attempt_delta(previous, &summary));
    state.attempts.push(summary);
    state.target_fingerprint = Some(target_fingerprint.clone());
    state.e2e_current = result.passed;
    state.comparison_current = false;
    state.route = None;
    state.rule_plan = None;
    if result.passed {
        state.active_issue = None;
        state.phase = RewritePhase::ComparisonRecordingRequired;
        state.comparison_run_id = Some(artifacts::allocate_run_id(
            target_root,
            ManagedRecordingOperation::RecordComparison,
        )?);
    } else {
        state.active_issue = Some(issue::from_e2e(&state.api, &result, target_fingerprint));
        state.phase = RewritePhase::ImplementationRequired;
    }
    state.bump();
    Ok(())
}

fn compare_and_transition(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let run_id = state
        .comparison_run_id
        .as_deref()
        .context("comparison phase has no run id")?;
    let case_source = artifacts::comparison_run(target_root, run_id);
    let policy = target_root.join(".traffic-e2e/verification.yaml");
    let report = verify_comparison_recording(ComparisonVerificationOptions {
        report: case_source.join("comparison-report.json"),
        case_source,
        policy: policy.clone(),
    })?;
    update_comparison_progress(
        &report,
        &policy
            .parent()
            .context("verification policy has no parent")?
            .join("comparison-progress.yaml"),
    )?;
    state.comparison_current = report.passed;
    if report.passed {
        state.active_issue = None;
        state.phase = RewritePhase::SliceComplete;
    } else {
        let observation = report
            .representative_difference
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let pointer = observation
            .as_ref()
            .and_then(|value| value.get("pointer"))
            .and_then(Value::as_str)
            .unwrap_or("<comparison>");
        let id = issue::id(&state.api, "comparison", pointer);
        state.active_issue = Some(RewriteIssue {
            id,
            kind: RewriteIssueKind::Comparison,
            owner: RewriteIssueOwner::TargetCode,
            summary: format!(
                "comparison has {} candidate difference(s) and {} inconclusive case(s)",
                report.counts.failed, report.counts.inconclusive
            ),
            pointer_pattern: (pointer != "<comparison>").then(|| issue::normalize_pointer(pointer)),
            representative: None,
            possible_causes: vec![
                "target_behavior".to_string(),
                "intentional_source_nondeterminism".to_string(),
                "source_changed_during_comparison".to_string(),
                "verification_policy_gap".to_string(),
            ],
            observed_target_fingerprint: fingerprint::repository_fingerprint(target_root)?,
            attempt: state.attempts.last().map_or(0, |attempt| attempt.attempt),
            comparison_observation: observation,
        });
        state.target_fingerprint = Some(fingerprint::repository_fingerprint(target_root)?);
        state.phase = RewritePhase::ImplementationRequired;
    }
    state.bump();
    Ok(())
}

fn attempt_delta(
    previous: &RewriteAttemptSummary,
    current: &RewriteAttemptSummary,
) -> RewriteAttemptDelta {
    let passed_delta =
        current.counts.response_passed as i64 - previous.counts.response_passed as i64;
    let nonpassing_delta =
        current.counts.response_nonpassing as i64 - previous.counts.response_nonpassing as i64;
    RewriteAttemptDelta {
        previous_attempt: previous.attempt,
        current_attempt: current.attempt,
        response_passed_delta: passed_delta,
        response_nonpassing_delta: nonpassing_delta,
        improved: passed_delta > 0 || nonpassing_delta < 0,
        regressed: passed_delta < 0 || nonpassing_delta > 0,
    }
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
pub(in crate::rewrite) fn test_state() -> RewriteState {
    RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: "rewrite-test".to_string(),
        phase: RewritePhase::RecordingRequired,
        api: "GET /api".to_string(),
        source_route: "/api".to_string(),
        recording_run_id: "20260802000000".to_string(),
        recording_rejection: None,
        recording_settings: RewriteRecordingSettings::default(),
        recording_request_reason: None,
        comparison_run_id: None,
        comparison_rejection: None,
        case_source: None,
        source_revision: None,
        group_id: None,
        target_fingerprint: None,
        attempts: Vec::new(),
        attempt_delta: None,
        active_issue: None,
        rule_plan: None,
        route: None,
        e2e_current: false,
        comparison_current: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_patterns_replace_only_array_indices() {
        assert_eq!(issue::normalize_pointer("/users/17/id"), "/users/*/id");
        assert_eq!(issue::normalize_pointer("/v2/created_at"), "/v2/created_at");
    }

    #[test]
    fn action_commands_are_argv_and_do_not_contain_secret_values() {
        let state = test_state();
        let value = serde_json::to_value(action::for_state(&state)).unwrap();
        assert_eq!(
            value.pointer("/action/command/required_env_names/0"),
            Some(&Value::String("TRAFFIC_E2E_ENCRYPTION_KEY_B64".to_string()))
        );
        assert_eq!(
            value.pointer("/action/command/argv/10"),
            Some(&Value::String("--case-limit".to_string()))
        );
        assert_eq!(
            value.pointer("/action/command/argv/11"),
            Some(&Value::String("100".to_string()))
        );
        assert!(!value.to_string().contains("encryption-key-value"));
    }

    #[test]
    fn rejected_recording_action_allocates_a_replacement_without_exposing_paths() {
        let mut state = test_state();
        state.recording_rejection = Some(artifacts::recording_rejection(&anyhow::anyhow!(
            "standard recording published no cases"
        )));
        state.recording_run_id = "20260802000001".to_string();

        let value = serde_json::to_value(action::for_state(&state)).unwrap();
        assert_eq!(
            value.pointer("/action/command/argv/5"),
            Some(&serde_json::json!("20260802000001"))
        );
        let summary = value.pointer("/action/summary").unwrap().as_str().unwrap();
        assert!(summary.contains("published no cases"));
        assert!(!summary.contains(".traffic-e2e"));
    }

    #[test]
    fn status_mismatch_causes_do_not_suggest_collection_or_dynamic_rules() {
        let causes =
            issue::response_possible_causes(Some(crate::ResponseDifferenceKind::StatusMismatch));
        assert!(causes.iter().any(|cause| cause.contains("authentication")));
        assert!(!causes.iter().any(|cause| cause.contains("collection")));
        assert!(!causes.iter().any(|cause| cause.contains("nondeterminism")));
    }

    #[test]
    fn incomplete_work_never_allows_terminal_output() {
        let state = test_state();
        assert!(!action::for_state(&state).terminal_allowed);
    }

    #[test]
    fn locked_workflow_returns_only_a_public_recovery_command() {
        let value = serde_json::to_value(action::recovery_required()).unwrap();
        assert_eq!(
            value.pointer("/action/command/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "recover"]))
        );
        assert!(!value.to_string().contains(".traffic-e2e/local"));
        assert_eq!(
            value.pointer("/action/resume/argv"),
            Some(&serde_json::json!(["traffic-e2e", "rewrite", "next"]))
        );
    }
}
