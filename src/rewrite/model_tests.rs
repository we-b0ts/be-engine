use std::collections::BTreeSet;
use std::path::PathBuf;

use super::*;

#[test]
fn older_state_uses_bounded_recording_defaults() {
    let mut value = serde_json::to_value(crate::rewrite::test_state()).unwrap();
    let object = value.as_object_mut().unwrap();
    for field in [
        "recording_settings",
        "recording_request_reason",
        "recording_input_case_source",
        "recording_input_diagnosis",
        "case_inventory_id",
        "recording_apis",
        "api_inventory",
        "current_api_index",
        "parked_slices",
        "worker_bindings",
        "process_outputs",
        "api_catalog_initialized",
        "api_catalog",
        "case_pattern_identification",
    ] {
        object.remove(field);
    }

    let state: RewriteState = serde_json::from_value(value).unwrap();

    assert_eq!(state.recording_settings.duration_seconds.get(), 60);
    assert_eq!(state.recording_settings.per_api_case_limit.get(), 100);
    assert!(state.recording_request_reason.is_none());
    assert!(state.recording_input_case_source.is_none());
    assert!(state.recording_input_diagnosis.is_none());
    assert!(state.case_inventory_id.is_none());
    assert!(state.recording_apis.is_empty());
    assert!(state.api_inventory.is_empty());
    assert!(state.current_api_index.is_none());
    assert!(state.parked_slices.is_empty());
    assert!(state.worker_bindings.is_empty());
    assert!(state.process_outputs.inventory.is_empty());
    assert!(!state.api_catalog_initialized);
    assert!(state.api_catalog.is_empty());
    assert!(state.case_pattern_identification.is_none());
    assert!(state.target_quality_fingerprint.is_none());
}

#[test]
fn implementation_action_has_one_stable_public_shape() {
    let command = RewriteCommandSpec {
        cwd: PathBuf::from("/target"),
        argv: vec!["backend-rewrite".to_string(), "status".to_string()],
        required_env_names: Vec::new(),
    };
    let action = RewriteAction::ImplementationRequired {
        summary: "response status differs".to_string(),
        issue: RewriteIssue {
            id: "issue-response".to_string(),
            kind: RewriteIssueKind::Response,
            owner: RewriteIssueOwner::TargetCode,
            summary: "response status differs".to_string(),
            pointer_pattern: Some("/status".to_string()),
            representative: None,
            egress_rejections: None,
            recorder_capture_diagnosis: None,
            response_diagnosis: Some(E2eResponseDifferenceDiagnosis {
                total_differences: 7,
                indexed_differences: 7,
                omitted_differences: 0,
                failure_clusters: vec![crate::E2eFailureCluster {
                    pointer_pattern: "/users/*/tree".to_string(),
                    difference_kind: crate::ResponseDifferenceKind::MissingActual,
                    affected_cases: 3,
                    occurrences: 5,
                    representative_case_id: "case-1".to_string(),
                    representative_pointer: "/users/0/tree".to_string(),
                }],
                omitted_failure_clusters: 0,
            }),
            possible_causes: vec!["target behavior differs".to_string()],
            observed_target_fingerprint: "fnv1a64:target".to_string(),
            attempt: 2,
            comparison_observation: None,
        },
        worker: RewriteWorkerDispatchView {
            binding_id: "worker-binding".to_string(),
            dispatch_id: "worker-dispatch".to_string(),
            work_scope: RewriteWorkScope::Api {
                api: "GET /api".to_string(),
            },
            state: RewriteWorkerDispatchState::DispatchRequired,
            blocking_reason: Some(RewriteWorkerBlockingReason::WorkerDispatchUnconfirmed),
            requested_api: None,
            agent_name: None,
        },
        confirm_worker: Some(command.clone()),
        report_worker: command.clone(),
        acceptance: command,
    };

    let value = serde_json::to_value(&action).unwrap();
    let keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from(["commands", "details", "kind", "summary"])
    );
    assert_eq!(
        value.pointer("/details/issue_id"),
        Some(&serde_json::json!("issue-response"))
    );
    assert_eq!(
        value.pointer("/details/work_scope/kind"),
        Some(&serde_json::json!("api"))
    );
    for field in [
        "possible_causes",
        "response_diagnosis",
        "representative",
        "comparison_observation",
    ] {
        assert!(value["details"].get(field).is_none());
    }
    assert!(value["commands"].get("evidence").is_none());
    assert_eq!(
        value.pointer("/details/worker/state"),
        Some(&serde_json::json!("dispatch_required"))
    );
    assert_eq!(
        value.pointer("/commands/confirm_worker/argv/1"),
        Some(&serde_json::json!("status"))
    );
    assert!(value.get("issue").is_none());
    assert!(value.get("evidence_commands").is_none());
    assert!(value.get("acceptance").is_none());

    let status = serde_json::to_value(RewriteStatusReport {
        schema_version: ACTION_SCHEMA_VERSION,
        pending: 0,
        initialized: true,
        workflow: None,
        api_inventory: None,
        process_output_inventory: None,
        latest_focused_e2e: None,
        e2e_current: false,
        comparison_current: false,
        terminal_allowed: false,
        action,
    })
    .unwrap();
    assert_eq!(status.get("schema_version"), Some(&serde_json::json!(28)));
    assert!(status.get("active_issue").is_none());
    assert!(status.get("next").is_none());
}
