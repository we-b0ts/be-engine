use std::fs;
use std::path::{Path, PathBuf};

use super::model::{
    RewritePhase, RewriteRecordingSettings, RewriteSliceState, RewriteState, STATE_VERSION,
};

pub(in crate::rewrite) fn install_source_snapshot(target_root: &Path) -> String {
    crate::source_snapshot::test_fixture::install(target_root)
}

pub(in crate::rewrite) fn test_state() -> RewriteState {
    RewriteState {
        version: STATE_VERSION,
        revision: 1,
        workflow_id: "rewrite-test".to_string(),
        dependency_review: Default::default(),
        regression: None,
        recording_apis: vec!["GET /api".to_string()],
        api_inventory: Vec::new(),
        revalidation_round: None,
        pre_revalidation_review: None,
        skipped_api_statuses: Default::default(),
        source_route_bindings: std::collections::BTreeMap::new(),
        current_api_index: None,
        parked_slices: std::collections::BTreeMap::new(),
        worker_bindings: std::collections::BTreeMap::new(),
        implementers: None,
        repository_analysis: None,
        group_replay: None,
        last_group_replay: None,
        source_review_rework: std::collections::BTreeMap::new(),
        worker_event_revision: 0,
        rule_plan_event_revision: 0,
        api_catalog_initialized: false,
        api_catalog: std::collections::BTreeSet::new(),
        case_pattern_identification: None,
        case_pattern_analysis: None,
        target_quality_fingerprint: None,
        delivery_review_required: false,
        recording_run_id: "20260802000000".to_string(),
        recording_after_run_id: None,
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
            case_source: None,
            case_inventory_id: None,
            source_revision: None,
            group_id: None,
            target_fingerprint: None,
            replay_identity: None,
            attempts: Vec::new(),
            engine_retry_fingerprints: Default::default(),
            engine_retry_running: false,
            attempt_delta: None,
            active_issue: None,
            rule_plan: None,
            dependency_rule_plan: None,
            recorder_capture_plan: None,
            route: None,
            system_repair_accepted: false,
            rule_replay_pending: false,
            e2e_current: false,
        },
    }
}

pub(in crate::rewrite) fn install_project_config(
    target_root: &Path,
    pr_base: &str,
    recorder: crate::config::AppConfig,
    _quality_gates: Option<serde_json::Value>,
) {
    let target = serde_json::json!({
        "dockerfile": ".traffic-e2e/Dockerfile.target",
        "startup": {},
    });
    let document = serde_json::json!({
        "version": 18,
        "project": {
            "policy": ".traffic-e2e/policy.yaml",
            "source": { "snapshot": ".traffic-e2e/local/source" },
            "target": target,
            "replay": {},
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
        directory.join("policy.yaml"),
        crate::config::native_policy::empty_policy().unwrap(),
    )
    .unwrap();
}

pub(in crate::rewrite) fn set_managed_paths(target_root: &Path, paths: &[&str]) {
    let path = target_root.join(".traffic-e2e/project.yaml");
    let mut document: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    document["project"]["delivery"]["managed_paths"] = serde_yaml::to_value(paths).unwrap();
    fs::write(path, serde_yaml::to_string(&document).unwrap()).unwrap();
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
