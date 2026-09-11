use std::fs;
use std::path::{Path, PathBuf};

use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};

pub(in crate::rewrite) fn test_state() -> RewriteState {
    RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: "rewrite-test".to_string(),
        recording_apis: vec!["GET /api".to_string()],
        api_inventory: Vec::new(),
        skipped_api_statuses: Default::default(),
        source_route_bindings: std::collections::BTreeMap::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        source_review_rework: std::collections::BTreeMap::new(),
        worker_event_revision: 0,
        process_outputs: Default::default(),
        api_catalog_initialized: false,
        api_catalog: std::collections::BTreeSet::new(),
        case_pattern_identification: None,
        target_quality_fingerprint: None,
        delivery_review_required: false,
        recording_run_id: "20260802000000".to_string(),
        require_comparison: true,
        recording_rejection: None,
        recording_settings: RewriteRecordingSettings::default(),
        recording_request_reason: None,
        recording_input_case_source: Some(PathBuf::from("recording-input")),
        recording_input_diagnosis: None,
        recording_refresh: None,
        active_slice: RewriteSliceState {
            phase: RewritePhase::RecordingRequired,
            api: "GET /api".to_string(),
            source_route: "/api".to_string(),
            comparison_run_id: None,
            comparison_rejection: None,
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            attempts: Vec::new(),
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            system_repair_accepted: false,
            e2e_current: false,
            comparison_current: false,
        },
    }
}

pub(in crate::rewrite) fn install_project_config(
    target_root: &Path,
    pr_base: &str,
    recorder: crate::config::AppConfig,
    quality_gates: Option<serde_json::Value>,
) {
    let mut target = serde_json::json!({
        "dockerfile": ".traffic-e2e/Dockerfile.e2e",
        "startup": {},
    });
    if let Some(quality_gates) = quality_gates {
        target["quality_gates"] = quality_gates;
    }
    let document = serde_json::json!({
        "version": 17,
        "project": {
            "source": { "snapshot": ".traffic-e2e/local/source" },
            "target": target,
            "replay": { "policy": ".traffic-e2e/verification.yaml" },
            "recording": {
                "rule": "http-rule",
                "source_traffic_policy": "source-traffic-policy.yaml"
            },
            "delivery": { "pr_base": pr_base },
            "state": { "runtime_root": "local/runtime" }
        },
        "recorder": recorder,
    });
    let directory = target_root.join(".traffic-e2e");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("project.yaml"),
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("source-traffic-policy.yaml"),
        crate::config::SourceTrafficPolicyConfig::empty()
            .render()
            .unwrap(),
    )
    .unwrap();
}

pub(in crate::rewrite) fn managed_test_recorder() -> crate::config::AppConfig {
    let mut recorder = crate::config::AppConfig::default();
    recorder.http_gateway.ready.enabled = true;
    recorder.http_gateway.ready.path = "/healthz".to_string();
    recorder.http_gateway.ready.success_status = 404;
    recorder.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
        name: Some("http-rule".to_string()),
        methods: vec!["GET".to_string()],
        path_prefixes: vec!["/".to_string()],
        ..Default::default()
    }];
    recorder
}
