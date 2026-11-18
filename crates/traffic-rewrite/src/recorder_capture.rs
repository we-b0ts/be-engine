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
    RewriteContext, action, evidence, fingerprint, inventory, recording, traffic_operation,
};

pub(crate) mod http_response;
use http_response::HttpResponseCaptureSpec;
pub use http_response::{
    RewriteHttpResponseCapturePlanOptions, plan_rewrite_http_response_capture,
};

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

pub(super) fn plan_http_response(
    target_root: &Path,
    state: &mut RewriteState,
    evidence_id: String,
    source_evidence: String,
    spec: HttpResponseCaptureSpec,
) -> Result<RewriteRecorderCaptureReport> {
    let endpoint = spec.rule.authorities[0].clone();
    let issue = capture_issue(state)?;
    validate_plan_evidence(target_root, state, &issue.id, &evidence_id)?;
    validate_single_line("source evidence", &source_evidence)?;
    let source_revision = state
        .source_revision
        .clone()
        .context("recorder capture planning requires a finalized source revision")?;
    let project_config_revision = fingerprint::project_config_revision(target_root)?;
    let traffic_plan =
        http_response::Plan::build(target_root, &spec, &source_revision, &source_evidence)?;
    ensure!(
        fingerprint::project_config_revision(target_root)? == project_config_revision,
        "recorder config changed during capture planning; rerun plan"
    );
    let resource_identity = traffic_plan.report["resource_identity"]
        .as_str()
        .context("HTTP response capture plan has no resource identity")?
        .to_owned();
    let target_fingerprint = fingerprint::repository_fingerprint(target_root)?;
    let record = RewriteRecorderCapturePlanRecord {
        id: format!(
            "recorder-capture-plan-{}",
            fingerprint::id(&[
                &state.workflow_id,
                &issue.id,
                &evidence_id,
                &endpoint,
                &source_evidence,
                &source_revision,
                &project_config_revision,
                &resource_identity,
                &target_fingerprint,
                &http_response::identity(&spec),
            ])
            .trim_start_matches("fnv1a64:")
        ),
        issue_id: issue.id.clone(),
        evidence_id: evidence_id,
        endpoint: endpoint,
        source_evidence: source_evidence,
        source_revision,
        project_config_revision,
        resource_identity,
        target_fingerprint,
        http_response: Some(spec),
    };
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = Some(record.clone());
    state.bump();
    Ok(RewriteRecorderCaptureReport {
        plan_id: record.id.clone(),
        issue_id: issue.id,
        api: state.api.clone(),
        traffic_e2e_report: traffic_plan.report,
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
    let spec = record
        .http_response
        .as_ref()
        .context("Breeze snapshot capture plans have been retired")?;
    http_response::revalidate(target_root, state, spec)?;
    let plan = http_response::Plan::build(
        target_root,
        spec,
        &record.source_revision,
        &record.source_evidence,
    )?;
    ensure!(
        plan.report["resource_identity"].as_str() == Some(record.resource_identity.as_str()),
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
            RewriteIssueKind::Response | RewriteIssueKind::Replay | RewriteIssueKind::Dependency
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

fn project_config(target_root: &Path) -> PathBuf {
    target_root.join(".traffic-e2e/project.yaml")
}

fn source_traffic_policy_path(target_root: &Path) -> Result<PathBuf> {
    crate::config::resolve_unified_policy_path(&project_config(target_root))
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
            api: None,
            kind: super::model::RewriteAdvanceKind::Workflow,
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
    if state.phase == RewritePhase::RecordingRequired
        || state
            .current_api_index
            .and_then(|index| state.api_inventory.get(index))
            .is_some()
    {
        action::next_command(target_root)
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
    use super::*;
    use crate::model::{RewriteApiProgress, RewriteApiStatus, RewriteDependencyRuleAppliedRecord};

    #[test]
    fn waiting_api_status_exposes_the_consolidated_refresh_state() {
        let mut state = crate::test_state();
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
}
