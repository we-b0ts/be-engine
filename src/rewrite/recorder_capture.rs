use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::model::{
    RewriteAction, RewriteIssue, RewriteIssueKind, RewritePhase,
    RewriteRecorderCaptureAppliedRecord, RewriteRecorderCapturePlanRecord,
    RewriteRecorderCaptureReport, RewriteRecordingRefreshState, RewriteState,
};
use super::store::RewriteStore;
use super::{
    RewriteContext, action, evidence, fingerprint, inventory, recording, recording_action,
    traffic_operation,
};
use crate::{BreezeEndpointCaptureFeedback, plan_breeze_endpoint_capture};

mod capture_plan;
pub(in crate::rewrite) mod http_response;
use capture_plan::CapturePlan;
use http_response::HttpResponseCaptureSpec;
pub use http_response::{
    RewriteHttpResponseCapturePlanOptions, plan_rewrite_http_response_capture,
};

#[derive(Debug, Clone)]
pub struct RewriteRecorderCapturePlanOptions {
    pub evidence_id: String,
    pub endpoint: String,
    pub source_evidence: String,
}

pub fn plan_rewrite_recorder_capture(
    context: RewriteContext,
    options: RewriteRecorderCapturePlanOptions,
) -> Result<RewriteRecorderCaptureReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    inventory::initialize_legacy(&mut state);
    let api = inventory::api_for_evidence_id(&target_root, &state, &options.evidence_id)
        .context("recorder-capture evidence is stale or belongs to no concurrent API work item")?;
    super::worker::ensure_api_confirmed(&state, &api, "planning recorder capture")?;
    let report =
        inventory::with_slice_mut(&mut state, &api, |state| plan(&target_root, state, options))?;
    store.save(&state)?;
    Ok(report)
}

pub fn apply_rewrite_recorder_capture(
    context: RewriteContext,
    plan_id: &str,
) -> Result<RewriteRecorderCaptureReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    inventory::initialize_legacy(&mut state);
    ensure_traffic_idle(&target_root)?;
    let api = inventory::api_for_recorder_capture_plan(&state, plan_id)
        .context("recorder-capture plan is stale or belongs to no concurrent API work item")?;
    let applied = inventory::with_slice_mut(&mut state, &api, |state| {
        apply(&target_root, state, plan_id)
    })?;
    inventory::rebase_target_fingerprint(
        &mut state,
        &applied.previous_target_fingerprint,
        &applied.current_target_fingerprint,
    );
    let runnable = inventory::mark_awaiting_recording_refresh(&mut state, &api)?;
    store.save(&state)?;
    if !runnable {
        recording::begin_pending_capture_refresh(&target_root, &mut state)?;
    }
    let report = RewriteRecorderCaptureReport {
        plan_id: applied.plan_id,
        issue_id: applied.issue_id,
        api: applied.api,
        traffic_e2e_report: applied.traffic_e2e_report,
        recording_refresh_pending: state.recording_refresh.is_some(),
        awaiting_apis: awaiting_apis(&state),
        next_command: next_command(&target_root, &state),
    };
    store.save(&state)?;
    Ok(report)
}

#[derive(Debug)]
pub(super) struct AppliedRecorderCapture {
    pub plan_id: String,
    pub issue_id: String,
    pub api: String,
    pub traffic_e2e_report: Value,
    pub previous_target_fingerprint: String,
    pub current_target_fingerprint: String,
}

pub(super) fn plan(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRecorderCapturePlanOptions,
) -> Result<RewriteRecorderCaptureReport> {
    plan_with_capture_requirement(target_root, state, options, false, None)
}

pub(super) fn plan_missing_recorded_resource(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRecorderCapturePlanOptions,
) -> Result<RewriteRecorderCaptureReport> {
    plan_with_capture_requirement(target_root, state, options, true, None)
}

fn plan_with_capture_requirement(
    target_root: &Path,
    state: &mut RewriteState,
    options: RewriteRecorderCapturePlanOptions,
    require_current_bypass: bool,
    http_response: Option<HttpResponseCaptureSpec>,
) -> Result<RewriteRecorderCaptureReport> {
    let issue = capture_issue(state)?;
    validate_plan_evidence(target_root, state, &issue.id, &options.evidence_id)?;
    validate_single_line("source evidence", &options.source_evidence)?;
    let source_revision = state
        .source_revision
        .clone()
        .context("recorder capture planning requires a finalized source revision")?;
    let project_config_revision = fingerprint::project_config_revision(target_root)?;
    let traffic_plan = if let Some(spec) = &http_response {
        CapturePlan::HttpResponse(http_response::Plan::build(
            target_root,
            spec,
            &source_revision,
            &options.source_evidence,
        )?)
    } else {
        CapturePlan::Breeze(Box::new(plan_breeze_endpoint_capture(
            BreezeEndpointCaptureFeedback {
                project_config_path: project_config(target_root),
                rules_path: source_traffic_policy_path(target_root),
                endpoint: options.endpoint.clone(),
                source_revision: source_revision.clone(),
                source_evidence: options.source_evidence.clone(),
            },
        )?))
    };
    if require_current_bypass {
        ensure!(
            traffic_plan.has_current_bypass(),
            "backend endpoint {:?} resolves to Breeze resource {:?}, but all of its backend domains are already captured and are not currently bypassed",
            options.endpoint,
            traffic_plan.resource_identity()
        );
    }
    ensure!(
        fingerprint::project_config_revision(target_root)? == project_config_revision,
        "recorder config changed during capture planning; rerun plan"
    );
    let resource_identity = traffic_plan.resource_identity().to_string();
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let record = RewriteRecorderCapturePlanRecord {
        id: format!(
            "recorder-capture-plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &options.evidence_id,
                &options.endpoint,
                &options.source_evidence,
                &source_revision,
                &project_config_revision,
                &resource_identity,
                &target_fingerprint,
                &http_response
                    .as_ref()
                    .map(http_response::identity)
                    .unwrap_or_default(),
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        evidence_id: options.evidence_id,
        endpoint: options.endpoint,
        source_evidence: options.source_evidence,
        source_revision,
        project_config_revision,
        resource_identity,
        target_fingerprint,
        http_response,
    };
    let traffic_e2e_report = traffic_plan.report()?;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = Some(record.clone());
    state.bump();
    Ok(RewriteRecorderCaptureReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        api: state.api.clone(),
        traffic_e2e_report,
        recording_refresh_pending: state.recording_refresh.is_some(),
        awaiting_apis: awaiting_apis(state),
        next_command: apply_command(target_root, &record.id),
    })
}

pub(super) fn apply(
    target_root: &Path,
    state: &mut RewriteState,
    plan_id: &str,
) -> Result<AppliedRecorderCapture> {
    let record = pending_plan_for_apply(state, plan_id)?;
    ensure!(
        state
            .recording_refresh
            .as_ref()
            .and_then(|refresh| refresh.recording_run_id.as_ref())
            .is_none(),
        "a full recording refresh has already started; wait for it to finish before applying another capture plan"
    );
    ensure!(
        fingerprint::project_config_revision(target_root)? == record.project_config_revision,
        "recorder config changed after capture planning; rerun plan"
    );
    ensure!(
        fingerprint::repository_fingerprint(target_root)? == record.target_fingerprint,
        "target repository changed after capture planning; rerun plan before applying"
    );
    if let Some(spec) = &record.http_response {
        http_response::revalidate(target_root, state, spec)?;
    }
    let plan = build_plan(target_root, &record)?;
    ensure!(
        plan.resource_identity() == record.resource_identity,
        "capture rule resolution changed after planning; rerun plan"
    );
    let report = plan.apply()?;
    let current_target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let config_revision = fingerprint::project_config_revision(target_root)?;
    let rules_revision = fingerprint::source_traffic_policy_revision(target_root)?;
    let api = state.api.clone();
    let baseline_case_source = state.case_source.clone();
    let refresh = state
        .recording_refresh
        .get_or_insert_with(|| RewriteRecordingRefreshState {
            applied: Vec::new(),
            dependency_rules: Vec::new(),
            baseline_case_source: baseline_case_source.clone(),
            project_config_revision: config_revision.clone(),
            source_traffic_policy_revision: rules_revision.clone(),
            recording_run_id: None,
        });
    refresh.project_config_revision = config_revision;
    refresh.source_traffic_policy_revision = rules_revision;
    if refresh.baseline_case_source.is_none() {
        refresh.baseline_case_source = baseline_case_source;
    }
    if !refresh
        .applied
        .iter()
        .any(|applied| applied.plan_id == record.id)
    {
        refresh.applied.push(RewriteRecorderCaptureAppliedRecord {
            plan_id: record.id.clone(),
            issue_id: record.issue_id.clone(),
            evidence_id: record.evidence_id.clone(),
            api,
            endpoint: record.endpoint.clone(),
            resource_identity: record.resource_identity.clone(),
            source_revision: record.source_revision.clone(),
            source_evidence: record.source_evidence.clone(),
        });
    }
    state.recorder_capture_plan = None;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.route = None;
    state.phase = RewritePhase::AwaitingRecordingRefresh;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
    Ok(AppliedRecorderCapture {
        plan_id: record.id,
        issue_id: record.issue_id,
        api: state.api.clone(),
        traffic_e2e_report: report,
        previous_target_fingerprint: record.target_fingerprint,
        current_target_fingerprint,
    })
}

pub(super) fn awaiting_apis(state: &RewriteState) -> Vec<String> {
    let mut apis = state
        .recording_refresh
        .as_ref()
        .map(|refresh| {
            refresh
                .applied
                .iter()
                .map(|record| record.api.clone())
                .chain(
                    refresh
                        .dependency_rules
                        .iter()
                        .map(|record| record.api.clone()),
                )
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    apis.sort();
    apis.dedup();
    apis
}

pub(super) fn capture_issue(state: &RewriteState) -> Result<RewriteIssue> {
    ensure!(
        state.phase == RewritePhase::ImplementationRequired,
        "recorder capture planning requires an active implementation issue"
    );
    let issue = state
        .active_issue
        .clone()
        .context("rewrite workflow has no active issue")?;
    ensure!(
        matches!(
            issue.kind,
            RewriteIssueKind::Response
                | RewriteIssueKind::Replay
                | RewriteIssueKind::Dependency
                | RewriteIssueKind::Comparison
        ),
        "recorder capture planning is not valid for active issue {:?}",
        issue.kind
    );
    Ok(issue)
}

fn pending_plan_for_apply(
    state: &RewriteState,
    plan_id: &str,
) -> Result<RewriteRecorderCapturePlanRecord> {
    let record = state
        .recorder_capture_plan
        .clone()
        .context("rewrite workflow has no pending recorder capture plan")?;
    ensure!(
        record.id == plan_id,
        "recorder capture plan is stale or belongs to another issue"
    );
    let issue = capture_issue(state)?;
    ensure!(
        issue.id == record.issue_id,
        "active rewrite issue changed after recorder capture planning"
    );
    Ok(record)
}

pub(super) fn validate_plan_evidence(
    target_root: &Path,
    state: &RewriteState,
    issue_id: &str,
    evidence_id: &str,
) -> Result<()> {
    if state
        .recorder_capture_plan
        .as_ref()
        .is_some_and(|plan| plan.issue_id == issue_id && plan.evidence_id == evidence_id)
    {
        return Ok(());
    }
    let valid = evidence::commands(target_root, state)
        .into_iter()
        .any(|command| {
            evidence::query(target_root, state, &command.query_id)
                .is_ok_and(|report| report.evidence_id == evidence_id)
        });
    ensure!(
        valid,
        "recorder capture evidence is stale or belongs to another issue"
    );
    Ok(())
}

fn build_plan(
    target_root: &Path,
    record: &RewriteRecorderCapturePlanRecord,
) -> Result<CapturePlan> {
    if let Some(spec) = &record.http_response {
        return Ok(CapturePlan::HttpResponse(http_response::Plan::build(
            target_root,
            spec,
            &record.source_revision,
            &record.source_evidence,
        )?));
    }
    Ok(CapturePlan::Breeze(Box::new(plan_breeze_endpoint_capture(
        BreezeEndpointCaptureFeedback {
            project_config_path: project_config(target_root),
            rules_path: source_traffic_policy_path(target_root),
            endpoint: record.endpoint.clone(),
            source_revision: record.source_revision.clone(),
            source_evidence: record.source_evidence.clone(),
        },
    )?)))
}

fn project_config(target_root: &Path) -> PathBuf {
    target_root.join(".traffic-e2e/project.yaml")
}

fn source_traffic_policy_path(target_root: &Path) -> PathBuf {
    target_root.join(".traffic-e2e/source-traffic-policy.yaml")
}

pub(super) fn pending_plan_action(
    target_root: &Path,
    state: &RewriteState,
) -> Option<RewriteAction> {
    state
        .recorder_capture_plan
        .as_ref()
        .map(|plan| RewriteAction::PlanApplyRequired {
            summary: "apply the unchanged pending recorder-capture plan".to_string(),
            command: apply_command(target_root, &plan.id),
        })
}

pub(super) fn pending_refresh_action(target_root: &Path, state: &RewriteState) -> RewriteAction {
    if !inventory::has_runnable_work(state) {
        return RewriteAction::AdvanceRequired {
            summary: "all current API work is drained; schedule the consolidated recording refresh"
                .to_string(),
            command: action::next_command(target_root),
        };
    }
    let refresh = state
        .recording_refresh
        .as_ref()
        .expect("recording refresh phase requires applied capture plans");
    RewriteAction::RecordingRefreshPending {
        summary: format!(
            "{} is waiting for one consolidated fresh standard recording; continue other runnable APIs first",
            state.api
        ),
        plan_ids: refresh
            .applied
            .iter()
            .map(|record| record.plan_id.clone())
            .chain(
                refresh
                    .dependency_rules
                    .iter()
                    .map(|record| record.plan_id.clone()),
            )
            .collect(),
        resource_identities: refresh
            .applied
            .iter()
            .map(|record| record.resource_identity.clone())
            .collect(),
        status: action::status_command_for_api(target_root, Some(&state.api)),
    }
}

fn apply_command(target_root: &Path, plan_id: &str) -> super::model::RewriteCommandSpec {
    action::command(
        target_root,
        vec![
            "recorder-capture".to_string(),
            "apply".to_string(),
            plan_id.to_string(),
        ],
        Vec::new(),
    )
}

fn next_command(target_root: &Path, state: &RewriteState) -> super::model::RewriteCommandSpec {
    if state.phase == RewritePhase::RecordingRequired {
        recording_action::command(target_root, state, false)
    } else if let Some(api) = state
        .current_api_index
        .and_then(|index| state.api_inventory.get(index))
        .map(|item| item.api.as_str())
    {
        action::next_command_for_selected_api(target_root, state, api)
    } else {
        action::status_command(target_root)
    }
}

pub(super) fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && !value.contains(['\r', '\n']),
        "{label} must be a non-empty single line"
    );
    Ok(())
}

fn ensure_traffic_idle(target_root: &Path) -> Result<()> {
    match traffic_operation::state(target_root)? {
        traffic_operation::TrafficOperationState::Absent => Ok(()),
        traffic_operation::TrafficOperationState::Live(active) => anyhow::bail!(
            "traffic runtime is owned by {:?} operation {}; wait and inspect `backend-rewrite status` before applying recorder capture",
            active.kind,
            active.operation_id
        ),
        traffic_operation::TrafficOperationState::Stale(active) => anyhow::bail!(
            "traffic runtime has stale {:?} operation {}; execute `backend-rewrite recover` before applying recorder capture",
            active.kind,
            active.operation_id
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;
    use crate::rewrite::model::{
        RewriteApiProgress, RewriteApiStatus, RewriteAttemptDelta,
        RewriteDependencyRuleAppliedRecord, RewriteIssueOwner,
    };

    #[test]
    fn waiting_api_status_exposes_the_consolidated_refresh_state() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::AwaitingRecordingRefresh;
        state.recording_refresh = Some(RewriteRecordingRefreshState {
            applied: vec![RewriteRecorderCaptureAppliedRecord {
                plan_id: "capture-plan-a".to_string(),
                issue_id: "issue-a".to_string(),
                evidence_id: "evidence-a".to_string(),
                api: "GET /api".to_string(),
                endpoint: "counter.example.com:9332".to_string(),
                resource_identity: "counter-resource".to_string(),
                source_revision: "source-a".to_string(),
                source_evidence: "CounterService.java:88".to_string(),
            }],
            dependency_rules: vec![RewriteDependencyRuleAppliedRecord {
                plan_id: "dependency-plan-a".to_string(),
                issue_id: "issue-b".to_string(),
                evidence_id: "evidence-b".to_string(),
                api: "GET /api".to_string(),
                rule_name: "snapshot-get".to_string(),
                source_evidence: "Cache.java:42".to_string(),
            }],
            baseline_case_source: Some(PathBuf::from("old-recording")),
            project_config_revision: "fnv1a64:config".to_string(),
            source_traffic_policy_revision: "fnv1a64:rules".to_string(),
            recording_run_id: None,
        });
        state.api_inventory.push(RewriteApiProgress {
            api: "POST /other".to_string(),
            source_route: Some("/other".to_string()),
            status: RewriteApiStatus::Active,
            attempts: 0,
            e2e_current: false,
            comparison_current: false,
            verified_target_fingerprint: None,
        });

        let value = serde_json::to_value(action::for_state(Path::new("/target"), &state)).unwrap();

        assert_eq!(
            value.pointer("/action/kind"),
            Some(&serde_json::json!("recording_refresh_pending"))
        );
        assert_eq!(
            value.pointer("/action/details/plan_ids/0"),
            Some(&serde_json::json!("capture-plan-a"))
        );
        assert_eq!(
            value.pointer("/action/details/plan_ids/1"),
            Some(&serde_json::json!("dependency-plan-a"))
        );
        assert_eq!(
            value.pointer("/action/details/resource_identities/0"),
            Some(&serde_json::json!("counter-resource"))
        );
        assert_eq!(
            value.pointer("/action/commands/wait/argv"),
            Some(&serde_json::json!([
                "backend-rewrite",
                "--target-root",
                "/target",
                "wait",
                "--seconds",
                "30"
            ]))
        );
        assert_eq!(value["terminal_allowed"], false);

        state.api_inventory.clear();
        let drained =
            serde_json::to_value(action::for_state(Path::new("/target"), &state)).unwrap();
        assert_eq!(drained["action"]["kind"], "advance_required");
        assert_eq!(
            drained["action"]["commands"]["advance"]["argv"],
            serde_json::json!(["backend-rewrite", "--target-root", "/target", "next"])
        );
    }

    #[test]
    fn capture_plan_is_evidence_bound_stale_safe_and_applies_immediately() {
        let target = tempfile::tempdir().unwrap();
        let snapshot = target.path().join("snapshot");
        fs::create_dir_all(target.path().join(".traffic-e2e")).unwrap();
        fs::create_dir_all(target.path().join("src")).unwrap();
        fs::create_dir(&snapshot).unwrap();
        fs::write(
            snapshot.join("static.config+counter"),
            "123\ncounter\nbackends:\n- counter.example.com:9332\n",
        )
        .unwrap();
        let mut recorder = crate::config::AppConfig::default();
        recorder.dns_mock.enabled = true;
        recorder.dns_mock.bypass_strategies =
            vec![crate::config::DnsBypassStrategyConfig::Breeze {
                snapshot_dir: snapshot.clone(),
                capture_resources: Vec::new(),
            }];
        crate::rewrite::test_support::install_project_config(
            target.path(),
            "master",
            recorder,
            None,
        );
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
        state.source_revision = Some("source-image-1".to_string());
        state.target_fingerprint =
            Some(fingerprint::repository_fingerprint(target.path()).unwrap());
        state.attempt_delta = Some(RewriteAttemptDelta {
            previous_attempt: 1,
            current_attempt: 2,
            response_passed_delta: 0,
            response_nonpassing_delta: 0,
            improved: false,
            regressed: false,
        });
        state.active_issue = Some(RewriteIssue {
            id: "issue-counter".to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "counter response differs".to_string(),
            pointer_pattern: None,
            representative: None,
            egress_rejections: None,
            recorder_capture_diagnosis: None,
            response_diagnosis: None,
            possible_causes: Vec::new(),
            observed_target_fingerprint: state.target_fingerprint.clone().unwrap(),
            attempt: 2,
            comparison_observation: None,
        });
        let query_id = evidence::commands(target.path(), &state)
            .into_iter()
            .find(|command| command.query_id.contains("attempt-delta"))
            .unwrap()
            .query_id;
        let evidence_id = evidence::query(target.path(), &state, &query_id)
            .unwrap()
            .evidence_id;
        let config = target
            .path()
            .join(".traffic-e2e/source-traffic-policy.yaml");
        let original = fs::read_to_string(&config).unwrap();

        let planned = plan(
            target.path(),
            &mut state,
            RewriteRecorderCapturePlanOptions {
                evidence_id,
                endpoint: "counter.example.com:9332".to_string(),
                source_evidence: "src/CounterService.java:88 reads counter backend".to_string(),
            },
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&config).unwrap(), original);
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();
        assert!(
            apply(target.path(), &mut state, &planned.plan_id)
                .unwrap_err()
                .to_string()
                .contains("target repository changed")
        );
        assert_eq!(fs::read_to_string(&config).unwrap(), original);
        fs::write(
            target.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();

        let applied = apply(target.path(), &mut state, &planned.plan_id).unwrap();
        assert_eq!(applied.api, "GET /api");
        assert_eq!(state.phase, RewritePhase::AwaitingRecordingRefresh);
        assert!(
            fs::read_to_string(config)
                .unwrap()
                .contains("capture_resources")
        );
        assert_eq!(awaiting_apis(&state), ["GET /api"]);
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
