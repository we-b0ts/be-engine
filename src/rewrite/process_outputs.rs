use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::json;

use super::model::{
    RewriteApiStatus, RewriteIssue, RewriteIssueKind, RewriteIssueOwner, RewriteState,
};
use super::process_output_model::{
    RewriteProcessOutputEvidence, RewriteProcessOutputInventoryDetails,
    RewriteProcessOutputInventoryView, RewriteProcessOutputProgress, RewriteProcessOutputStatus,
    RewriteWorkScope,
};

pub(super) enum ProcessOutputActivation {
    Compared,
    Deferred,
}

pub(super) fn install(
    state: &mut RewriteState,
    configs: &[crate::process_output::ProcessOutputConfig],
) {
    state.process_outputs.inventory = workflow_configs(configs)
        .iter()
        .map(|config| RewriteProcessOutputProgress {
            id: config.id.clone(),
            status: RewriteProcessOutputStatus::Pending,
            attempts: 0,
            verified_target_fingerprint: None,
            issue: None,
        })
        .collect();
    state.process_outputs.current_id = None;
    state.process_outputs.latest_target_evidence = None;
}

pub(super) fn reset(state: &mut RewriteState) {
    state.process_outputs = Default::default();
}

pub(super) fn observe_target_evidence(
    state: &mut RewriteState,
    root: PathBuf,
    target_fingerprint: String,
) {
    state.process_outputs.latest_target_evidence = Some(RewriteProcessOutputEvidence {
        root,
        target_fingerprint,
    });
}

pub(super) fn defer_for_target_change(state: &mut RewriteState, target_fingerprint: &str) -> bool {
    let mut changed = false;
    for item in &mut state.process_outputs.inventory {
        let stale_complete = item.status == RewriteProcessOutputStatus::Complete
            && item.verified_target_fingerprint.as_deref() != Some(target_fingerprint);
        if stale_complete {
            item.status = RewriteProcessOutputStatus::RevalidationPending;
            item.verified_target_fingerprint = None;
            item.issue = None;
            if state.process_outputs.current_id.as_deref() == Some(item.id.as_str()) {
                state.process_outputs.current_id = None;
            }
            changed = true;
        }
    }
    if changed {
        state.bump();
    }
    changed
}

pub(super) fn next_eligible_id(state: &RewriteState) -> Option<&str> {
    let api_dispatch_complete = state.api_inventory.iter().all(|item| {
        matches!(
            item.status,
            RewriteApiStatus::ImplementationRequired | RewriteApiStatus::Complete
        ) || (state.current_api_index.is_some_and(|index| {
            state
                .api_inventory
                .get(index)
                .is_some_and(|current| current.api == item.api)
        }) && state.phase == super::model::RewritePhase::ImplementationRequired)
    });
    if api_dispatch_complete
        && let Some(item) = state
            .process_outputs
            .inventory
            .iter()
            .find(|item| item.status == RewriteProcessOutputStatus::Pending)
    {
        return Some(&item.id);
    }
    let apis_complete = !state.api_inventory.is_empty()
        && state
            .api_inventory
            .iter()
            .all(|item| item.status == RewriteApiStatus::Complete);
    if !apis_complete {
        return None;
    }
    state
        .process_outputs
        .inventory
        .iter()
        .find(|item| item.status == RewriteProcessOutputStatus::RevalidationPending)
        .map(|item| item.id.as_str())
}

pub(super) fn activate_and_compare(
    target_root: &Path,
    state: &mut RewriteState,
    id: &str,
    target_fingerprint: &str,
    configs: &[crate::process_output::ProcessOutputConfig],
) -> Result<ProcessOutputActivation> {
    ensure_inventory_matches(state, configs)?;
    let configs = workflow_configs(configs);
    let index = state
        .process_outputs
        .inventory
        .iter()
        .position(|item| item.id == id)
        .with_context(|| format!("process output inventory does not contain {id:?}"))?;
    let status = state.process_outputs.inventory[index].status;
    ensure!(
        matches!(
            status,
            RewriteProcessOutputStatus::Pending
                | RewriteProcessOutputStatus::ImplementationRequired
                | RewriteProcessOutputStatus::RevalidationPending
        ),
        "process output {id} is not available for verification"
    );
    if status == RewriteProcessOutputStatus::ImplementationRequired {
        let observed = state.process_outputs.inventory[index]
            .issue
            .as_ref()
            .context("implementation-required process output has no issue")?
            .observed_target_fingerprint
            .clone();
        if observed == target_fingerprint {
            state.process_outputs.current_id = Some(id.to_string());
            return Ok(ProcessOutputActivation::Deferred);
        }
        let item = &mut state.process_outputs.inventory[index];
        item.status = RewriteProcessOutputStatus::RevalidationPending;
        item.issue = None;
        state.process_outputs.current_id = None;
        state.bump();
        return Ok(ProcessOutputActivation::Deferred);
    }
    ensure_eligible(state, status, id)?;
    let evidence = state
        .process_outputs
        .latest_target_evidence
        .as_ref()
        .filter(|evidence| evidence.target_fingerprint == target_fingerprint)
        .cloned()
        .context(
            "current target process-output capture is missing; rerun the coordinator-owned API verification",
        )?;
    crate::process_output::validate_capture_set(
        &configs,
        crate::process_output::ProcessOutputCaptureSide::Target,
        &evidence.root,
        false,
    )?;
    let config = configs
        .iter()
        .find(|config| config.id == id)
        .context("process output configuration disappeared")?;
    let source_root = super::artifacts::recording_run(target_root, &state.recording_run_id)
        .join("process-outputs");
    let result = crate::process_output::compare_capture(config, &source_root, &evidence.root)?;
    let item = &mut state.process_outputs.inventory[index];
    item.attempts = item.attempts.saturating_add(1);
    if result.passed {
        item.status = RewriteProcessOutputStatus::Complete;
        item.verified_target_fingerprint = Some(target_fingerprint.to_string());
        item.issue = None;
        state.process_outputs.current_id = None;
    } else {
        let attempt = item.attempts;
        item.status = RewriteProcessOutputStatus::ImplementationRequired;
        item.verified_target_fingerprint = None;
        item.issue = Some(missing_issue(&result, target_fingerprint, attempt));
        state.process_outputs.current_id = Some(id.to_string());
    }
    state.bump();
    Ok(ProcessOutputActivation::Compared)
}

pub(super) fn comparison_issue(
    target_root: &Path,
    state: &RewriteState,
    target_fingerprint: &str,
    configs: &[crate::process_output::ProcessOutputConfig],
) -> Result<Option<RewriteIssue>> {
    let configs = crate::process_output::configs_for_observation(
        configs,
        crate::process_output::ProcessOutputObservation::Comparison,
    );
    if configs.is_empty() {
        return Ok(None);
    }
    let run_id = state
        .comparison_run_id
        .as_deref()
        .context("comparison process output has no run id")?;
    let root = super::artifacts::comparison_run(target_root, run_id).join("process-outputs");
    let source_root = root.join("source");
    let target_root = root.join("target");
    let attempt = state.attempts.last().map_or(0, |attempt| attempt.attempt);
    for config in &configs {
        let result = crate::process_output::compare_capture(config, &source_root, &target_root)?;
        if !result.passed {
            return Ok(Some(missing_issue(&result, target_fingerprint, attempt)));
        }
    }
    Ok(None)
}

fn ensure_eligible(
    state: &RewriteState,
    status: RewriteProcessOutputStatus,
    id: &str,
) -> Result<()> {
    match status {
        RewriteProcessOutputStatus::Pending => ensure!(
            next_eligible_id(state) == Some(id),
            "process output {id} is scheduled after every API work item is dispatched"
        ),
        RewriteProcessOutputStatus::RevalidationPending => ensure!(
            state
                .api_inventory
                .iter()
                .all(|item| item.status == RewriteApiStatus::Complete),
            "process output {id} revalidation waits for every API to complete"
        ),
        RewriteProcessOutputStatus::ImplementationRequired
        | RewriteProcessOutputStatus::Complete => {}
    }
    Ok(())
}

pub(super) fn ensure_inventory_matches(
    state: &RewriteState,
    configs: &[crate::process_output::ProcessOutputConfig],
) -> Result<()> {
    let configs = workflow_configs(configs);
    ensure!(
        state.process_outputs.inventory.len() == configs.len()
            && configs.iter().all(|config| {
                state
                    .process_outputs
                    .inventory
                    .iter()
                    .any(|item| item.id == config.id)
            }),
        "process output configuration changed after the standard recording; start a fresh workflow recording"
    );
    Ok(())
}

fn workflow_configs(
    configs: &[crate::process_output::ProcessOutputConfig],
) -> Vec<crate::process_output::ProcessOutputConfig> {
    crate::process_output::configs_for_observation(
        configs,
        crate::process_output::ProcessOutputObservation::BeforeShutdown,
    )
}

fn missing_issue(
    result: &crate::process_output::ProcessOutputComparisonResult,
    target_fingerprint: &str,
    attempt: u64,
) -> RewriteIssue {
    let recommended_checks = if result.id == "metrics-profile" {
        vec![
            "Verify that the metrics component is loaded by the target process.".to_string(),
            "Verify that metrics initialization and startup are executed.".to_string(),
            format!(
                "Verify that the configured output path is {}.",
                result.path.display()
            ),
        ]
    } else {
        vec![
            "Verify that the component responsible for this process output is loaded and started."
                .to_string(),
            format!(
                "Verify that the configured output path is {}.",
                result.path.display()
            ),
        ]
    };
    RewriteIssue {
        id: super::fingerprint::id(&[
            "rewrite-process-output-issue-v1",
            &result.id,
            result.classification,
            &result.path.to_string_lossy(),
        ]),
        kind: RewriteIssueKind::ProcessOutput,
        owner: RewriteIssueOwner::TargetCode,
        summary: format!(
            "the target process did not generate process output {} at {}",
            result.id,
            result.path.display()
        ),
        pointer_pattern: None,
        representative: None,
        response_diagnosis: None,
        possible_causes: recommended_checks,
        observed_target_fingerprint: target_fingerprint.to_string(),
        attempt,
        comparison_observation: Some(json!({
            "kind": "process_output_comparison",
            "classification": result.classification,
            "process_output_id": result.id,
            "path": result.path,
            "comparison": "regular_file_exists",
            "source": { "present": result.source_present },
            "candidate": { "present": result.target_present }
        })),
    }
}

pub(super) fn active_scope(state: &RewriteState) -> Option<RewriteWorkScope> {
    let scope = selected_scope(state)?;
    let RewriteWorkScope::ProcessOutput { id } = &scope else {
        unreachable!("selected process output scope has the wrong kind")
    };
    let item = state
        .process_outputs
        .inventory
        .iter()
        .find(|item| item.id == *id)?;
    (item.status == RewriteProcessOutputStatus::ImplementationRequired && item.issue.is_some())
        .then_some(scope)
}

pub(super) fn selected_scope(state: &RewriteState) -> Option<RewriteWorkScope> {
    state
        .process_outputs
        .current_id
        .as_ref()
        .map(|id| RewriteWorkScope::ProcessOutput { id: id.clone() })
}

pub(super) fn issue_for_scope<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a RewriteIssue> {
    let RewriteWorkScope::ProcessOutput { id } = scope else {
        return None;
    };
    state
        .process_outputs
        .inventory
        .iter()
        .find(|item| item.id == *id)
        .and_then(|item| item.issue.as_ref())
}

pub(super) fn scoped(state: &RewriteState, id: &str) -> Result<RewriteState> {
    ensure!(
        state
            .process_outputs
            .inventory
            .iter()
            .any(|item| item.id == id),
        "process output inventory does not contain {id:?}"
    );
    let mut scoped = state.clone();
    scoped.process_outputs.current_id = Some(id.to_string());
    Ok(scoped)
}

pub(super) fn all_complete(state: &RewriteState) -> bool {
    state
        .process_outputs
        .inventory
        .iter()
        .all(|item| item.status == RewriteProcessOutputStatus::Complete)
}

pub(super) fn view(state: &RewriteState) -> RewriteProcessOutputInventoryView {
    RewriteProcessOutputInventoryView {
        total: state.process_outputs.inventory.len(),
        completed: count(state, RewriteProcessOutputStatus::Complete),
        pending: count(state, RewriteProcessOutputStatus::Pending),
        implementation_required: count(state, RewriteProcessOutputStatus::ImplementationRequired),
        revalidation_pending: count(state, RewriteProcessOutputStatus::RevalidationPending),
        current_output: state.process_outputs.current_id.clone(),
    }
}

pub(super) fn details(state: &RewriteState) -> RewriteProcessOutputInventoryDetails {
    RewriteProcessOutputInventoryDetails {
        summary: view(state),
        items: state.process_outputs.inventory.clone(),
    }
}

fn count(state: &RewriteState, status: RewriteProcessOutputStatus) -> usize {
    state
        .process_outputs
        .inventory
        .iter()
        .filter(|item| item.status == status)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::model::{RewriteApiProgress, RewritePhase};

    #[test]
    fn initial_process_output_waits_only_for_api_dispatch() {
        let mut state = crate::rewrite::test_state();
        state.phase = RewritePhase::ImplementationRequired;
        state.api_inventory = vec![api("GET /a", RewriteApiStatus::Active)];
        state.current_api_index = Some(0);
        state.process_outputs.inventory = vec![output(RewriteProcessOutputStatus::Pending)];

        assert_eq!(next_eligible_id(&state), Some("metrics-profile"));

        state
            .api_inventory
            .push(api("GET /b", RewriteApiStatus::Pending));
        assert_eq!(next_eligible_id(&state), None);
    }

    #[test]
    fn active_workflow_rejects_a_new_unrecorded_process_output_config() {
        let mut state = crate::rewrite::test_state();
        state.api_inventory = vec![api("GET /a", RewriteApiStatus::Complete)];
        let configs = vec![crate::process_output::ProcessOutputConfig {
            id: "metrics-profile".to_string(),
            path: PathBuf::from("/data1/weibo/logs/profile.log"),
            comparison: crate::process_output::ProcessOutputComparison::RegularFileExists,
            observation: crate::process_output::ProcessOutputObservation::BeforeShutdown,
            max_bytes: 1024,
        }];

        let error = ensure_inventory_matches(&state, &configs).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("start a fresh workflow recording")
        );
        install(&mut state, &configs);
        ensure_inventory_matches(&state, &configs).unwrap();
    }

    #[test]
    fn comparison_outputs_are_verified_per_api_not_as_global_work() {
        let mut state = crate::rewrite::test_state();
        state.api_inventory = vec![api("GET /a", RewriteApiStatus::Complete)];
        let before_shutdown = process_output_config(
            "startup-report",
            crate::process_output::ProcessOutputObservation::BeforeShutdown,
        );
        let comparison = process_output_config(
            "metrics-profile",
            crate::process_output::ProcessOutputObservation::Comparison,
        );

        let configs = [before_shutdown, comparison];
        install(&mut state, &configs);

        assert_eq!(state.process_outputs.inventory.len(), 1);
        assert_eq!(state.process_outputs.inventory[0].id, "startup-report");
        ensure_inventory_matches(&state, &configs).unwrap();
    }

    #[test]
    fn comparison_output_missing_from_target_becomes_current_api_issue() {
        let target = tempfile::tempdir().unwrap();
        let mut state = crate::rewrite::test_state();
        let run_id = "20260822000000";
        state.comparison_run_id = Some(run_id.to_string());
        let config = process_output_config(
            "metrics-profile",
            crate::process_output::ProcessOutputObservation::Comparison,
        );
        let root = crate::rewrite::artifacts::comparison_run(target.path(), run_id)
            .join("process-outputs");
        crate::process_output::write_test_capture(
            &root.join("source"),
            &config,
            crate::process_output::ProcessOutputCaptureSide::Source,
            Some(b"source profile"),
        )
        .unwrap();
        crate::process_output::write_test_capture(
            &root.join("target"),
            &config,
            crate::process_output::ProcessOutputCaptureSide::Target,
            None,
        )
        .unwrap();

        let issue = comparison_issue(target.path(), &state, "target-a", &[config])
            .unwrap()
            .unwrap();

        assert_eq!(issue.kind, RewriteIssueKind::ProcessOutput);
        assert_eq!(issue.owner, RewriteIssueOwner::TargetCode);
        assert_eq!(
            issue
                .comparison_observation
                .as_ref()
                .unwrap()
                .pointer("/candidate/present"),
            Some(&serde_json::json!(false))
        );
    }

    #[test]
    fn stale_process_output_waits_for_all_apis_to_complete() {
        let mut state = crate::rewrite::test_state();
        state.api_inventory = vec![api("GET /a", RewriteApiStatus::ImplementationRequired)];
        state.process_outputs.inventory =
            vec![output(RewriteProcessOutputStatus::RevalidationPending)];
        assert_eq!(next_eligible_id(&state), None);

        state.api_inventory[0].status = RewriteApiStatus::Complete;
        assert_eq!(next_eligible_id(&state), Some("metrics-profile"));
    }

    #[test]
    fn target_change_defers_completed_output_but_preserves_a_worker_issue() {
        let mut state = crate::rewrite::test_state();
        let mut completed = output(RewriteProcessOutputStatus::Complete);
        completed.id = "startup-report".to_string();
        completed.verified_target_fingerprint = Some("target-a".to_string());
        let mut missing = output(RewriteProcessOutputStatus::ImplementationRequired);
        missing.issue = Some(missing_issue(
            &crate::process_output::ProcessOutputComparisonResult {
                id: "metrics-profile".to_string(),
                path: PathBuf::from("/data1/weibo/logs/profile.log"),
                passed: false,
                classification: "candidate_missing",
                source_present: true,
                target_present: false,
            },
            "target-a",
            1,
        ));
        state.process_outputs.inventory = vec![completed, missing];
        state.process_outputs.current_id = Some("metrics-profile".to_string());

        assert!(defer_for_target_change(&mut state, "target-b"));
        assert_eq!(
            state.process_outputs.inventory[0].status,
            RewriteProcessOutputStatus::RevalidationPending
        );
        assert_eq!(
            state.process_outputs.inventory[1].status,
            RewriteProcessOutputStatus::ImplementationRequired
        );
        assert_eq!(
            state.process_outputs.current_id.as_deref(),
            Some("metrics-profile")
        );
    }

    #[test]
    fn metrics_profile_missing_issue_gives_target_code_startup_checks() {
        let issue = missing_issue(
            &crate::process_output::ProcessOutputComparisonResult {
                id: "metrics-profile".to_string(),
                path: PathBuf::from("/data1/weibo/logs/profile.log"),
                passed: false,
                classification: "candidate_missing",
                source_present: true,
                target_present: false,
            },
            "target-a",
            1,
        );
        let json = serde_json::to_value(issue).unwrap();
        let text = json.to_string();

        assert_eq!(json["kind"], "process_output");
        assert_eq!(json["owner"], "target_code");
        assert!(text.contains("metrics component is loaded"));
        assert!(text.contains("initialization and startup are executed"));
        assert!(text.contains("/data1/weibo/logs/profile.log"));
        assert!(!text.to_ascii_lowercase().contains("permission"));
    }

    fn api(api: &str, status: RewriteApiStatus) -> RewriteApiProgress {
        RewriteApiProgress {
            api: api.to_string(),
            source_route: Some(api.split_once(' ').unwrap().1.to_string()),
            status,
            attempts: 0,
            e2e_current: false,
            comparison_current: false,
            verified_target_fingerprint: None,
        }
    }

    fn output(status: RewriteProcessOutputStatus) -> RewriteProcessOutputProgress {
        RewriteProcessOutputProgress {
            id: "metrics-profile".to_string(),
            status,
            attempts: 0,
            verified_target_fingerprint: None,
            issue: None,
        }
    }

    fn process_output_config(
        id: &str,
        observation: crate::process_output::ProcessOutputObservation,
    ) -> crate::process_output::ProcessOutputConfig {
        crate::process_output::ProcessOutputConfig {
            id: id.to_string(),
            path: PathBuf::from("/data1/weibo/logs/profile.log"),
            comparison: crate::process_output::ProcessOutputComparison::RegularFileExists,
            observation,
            max_bytes: 1024,
        }
    }
}
