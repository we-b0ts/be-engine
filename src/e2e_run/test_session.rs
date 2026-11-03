//! Synthetic shared-session evidence for engine regression tests.
use super::final_evidence::summarize_apis_without_aggregate;
use super::{model::*, store};
use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
use serde_json::json;
use std::{fs, path::Path, time::Duration};

pub(super) fn config(root: &Path) -> ResolvedProjectConfig {
    ResolvedProjectConfig {
        replay_case_no_progress_timeout: Duration::from_secs(5),
        replay_pre_match: true,
        replay_stream_timing: None,
        replay_stream_interval_cap_ms: crate::replay::DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS,
        replay_socketio_timing: Default::default(),
        target_dockerfile: root.join("Dockerfile"),
        target_build_contexts: Vec::new(),
        target_startup: Default::default(),
        target_runtime_outputs: Vec::new(),
        target_http_origin: "http://127.0.0.1:8081".into(),
        target_port: 8081,
        target_http_readiness_enabled: true,
        target_motan_upstream: None,
        target_motan_connect_timeout: Duration::from_secs(1),
        target_motan_request_timeout: Duration::from_secs(1),
        target_motan_limits: Default::default(),
        target_readiness_path: "/healthz".into(),
        target_readiness_status: 200,
        target_startup_timeout: Duration::from_secs(1),
        target_request_timeout: Duration::from_secs(1),
        target_max_response_bytes: 1024,
        replay_policy: root.join("policy.yaml"),
        replay_case_dependency_post_response_window: Duration::from_millis(10),
        max_failed_cases_per_api: crate::DEFAULT_MAX_FAILED_CASES_PER_API,
        replay_loading: Default::default(),
        replay_startup_timeout: Duration::from_secs(1),
        pr_base: "master".into(),
        quality_check: "cargo-clippy".into(),
        managed_paths: Vec::new(),
        recorder_config: root.join("project.yaml"),
        source_traffic_policy: root.join("policy.yaml"),
        runner_owned_response_assertions: true,
    }
}

pub(super) fn session(root: &Path) -> (RunLayout, CaseGroupInventory, ActiveRunState) {
    let source = root.join("recording");
    let latest = root.join("runtime/focused/latest");
    fs::create_dir_all(latest.join("reports")).unwrap();
    let groups = [("GET", "get-case"), ("OPTIONS", "options-case")]
        .into_iter()
        .map(|(method, id)| {
            let dir = source.join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("request.json"),
                json!({"method":method,"uri":"/api"}).to_string(),
            )
            .unwrap();
            fs::write(dir.join("expected-response.json"), "{}").unwrap();
            fs::write(dir.join("dependencies.jsonl"), "").unwrap();
            CanonicalCaseGroup {
                group_id: format!("{method} /api"),
                method: method.into(),
                source_route: "/api".into(),
                pattern: None,
                case_inventory_id: "inventory".into(),
                cases: vec![CanonicalCase {
                    case_id: id.into(),
                    case_dir: dir,
                    recorded_at: None,
                }],
            }
        })
        .collect();
    let inventory = CaseGroupInventory {
        case_source: source.clone(),
        source_revision: "source".into(),
        case_inventory_id: "inventory".into(),
        groups,
    };
    let mut state = ActiveRunState::new("run".into(), 1, &inventory, &latest);
    state.status = RunStatus::Failed;
    state.session_id = Some("session".into());
    state.replay_finalized = true;
    state.aggregate_complete = true;
    state.aggregate_clean = false;
    for case in &mut state.cases {
        case.status = CaseStatus::Failed;
        case.assertion_passed = Some(true);
        case.replay_clean = Some(false);
    }
    let layout = RunLayout {
        target_root: root.into(),
        run_key: "run".into(),
        case_source: source.clone(),
        progress_path: root.join("progress.yaml"),
        legacy_progress_path: root.join("legacy.yaml"),
        internal_root: root.join("runtime"),
        current_path: root.join("current"),
        run_root: root.join("runtime"),
        index_path: root.join("index.yaml"),
        group_index_path: root.join("groups.json"),
        active_dir: latest.clone(),
        latest_dir: latest,
    };
    summarize_apis_without_aggregate(&layout, &mut state, &inventory);
    let mut report = json!({
        "version":7,"case_dir":source,"session_id":"session","started_at":"2026-10-12T00:00:00Z",
        "finalized":true,"finalized_at":"2026-10-12T00:01:00Z","success_detail_limit":20,
        "selected_case_ids":["get-case","options-case"],
        "cases":[{"case_id":"get-case","status":"ended"},{"case_id":"options-case","status":"ended"}],
        "connections":0,"builtin_query_count":0,"matched_query_count":0,"matched_http_exchange_count":0,
        "builtin_queries":[],"matched_queries":[],"unmatched_queries":[],"unsupported_commands":[],
        "metadata_warnings":[],"unused_case_exchanges":[],"unused_global_exchanges":[],
        "matched_http_exchanges":[],"unmatched_http_requests":[],"unsupported_http_exchanges":[],
        "unused_global_http_exchanges":[],
        "unused_case_http_exchanges":(0..14).map(|_| json!({"case_id":"get-case",
            "target":{"host":"stream.test","port":443},"scheme":"https","method":"GET","uri":"/connect"})).collect::<Vec<_>>()
    });
    for protocol in ["redis", "memcached", "kafka", "motan"] {
        report[protocol] = json!({"connections":0,"matched_count":0,"matched":[],"unmatched":[],
            "unsupported":[],"unsafe_events":[],"unused_case":[],"unused_global":[]});
    }
    store::write_json(&state.replay_report, &report).unwrap();
    (layout, inventory, state)
}
