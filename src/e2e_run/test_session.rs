//! Synthetic shared-session evidence for engine regression tests.
use super::final_evidence::summarize_apis_without_aggregate;
use super::{model::*, store};
use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) fn install(root: &Path) -> super::E2eRunContext {
    install_with_recorded_coverage(root, false)
}

pub(crate) fn install_with_unprepared_api(root: &Path) -> super::E2eRunContext {
    install_with_recorded_coverage(root, true)
}

fn install_with_recorded_coverage(root: &Path, unprepared_api: bool) -> super::E2eRunContext {
    use std::process::{Command, Stdio};
    fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    fs::write(
        root.join(".traffic-e2e/Dockerfile.target"),
        "FROM scratch\n",
    )
    .unwrap();
    let mut recorder = crate::config::AppConfig::default();
    recorder.http_gateway.ready.enabled = true;
    recorder.http_gateway.rules = vec![crate::config::HttpGatewayRuleConfig {
        name: Some("http-rule".into()),
        methods: vec!["GET".into(), "OPTIONS".into()],
        path_prefixes: vec!["/".into()],
        ..Default::default()
    }];
    let document = json!({"version":18,"project":{
        "source":{"snapshot":".traffic-e2e/local/source"},
        "target":{"dockerfile":".traffic-e2e/Dockerfile.target","startup":{}},
        "policy":".traffic-e2e/policy.yaml",
        "replay":{},
        "delivery":{"pr_base":"master"},"state":{"runtime_root":"local/runtime"}},
        "recorder":recorder});
    fs::write(
        root.join(".traffic-e2e/project.yaml"),
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
    fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v2\nrules: []\n",
    )
    .unwrap();
    fs::write(
        root.join(".gitignore"),
        ".traffic-e2e/local/\nrecording/\nruntime/\n",
    )
    .unwrap();
    fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    for args in [
        vec!["init", "-q", "-b", "master"],
        vec!["config", "user.email", "test@example.com"],
        vec!["config", "user.name", "Traffic E2E Test"],
        vec!["add", "."],
        vec!["commit", "-q", "-m", "baseline"],
        vec!["switch", "-q", "-c", "feature"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .stdout(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    let (synthetic, _, original) = session(root);
    if unprepared_api {
        let dir = synthetic.case_source.join("unprepared-case");
        fs::create_dir_all(&dir).unwrap();
        store::write_json(
            &dir.join("request.json"),
            &json!({"method":"GET","uri":"/unprepared"}),
        )
        .unwrap();
        fs::write(dir.join("expected-response.json"), "{}").unwrap();
        fs::write(dir.join("dependencies.jsonl"), "").unwrap();
    }
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&original.replay_report).unwrap()).unwrap();
    report["replay_policy"] = json!({"path":root.join(".traffic-e2e/policy.yaml"),
        "fingerprint":crate::validate_replay_policy(&root.join(".traffic-e2e/policy.yaml")).unwrap().fingerprint,
        "expected_response":"assertions_only","unused_applicable_dependency_rule_ids":[]});
    let context = super::E2eRunContext {
        target_root: root.into(),
        case_source: synthetic.case_source.clone(),
        run_key: None,
    };
    for method in ["GET", "OPTIONS"] {
        super::prepare_e2e_run(super::E2eRunPrepareOptions {
            context: context.clone(),
            case_dir: context.case_source.clone(),
            method: method.into(),
            source_route: "/api".into(),
            pattern: None,
            source_revision: "source".into(),
        })
        .unwrap();
    }
    let (config, layout) = super::config::resolve_layout(root, &context.case_source, None).unwrap();
    let inventory = if unprepared_api {
        crate::case_group::load_case_group_inventory(&layout.group_index_path, &context.case_source)
    } else {
        crate::case_group::load_complete_case_group_inventory(
            &layout.group_index_path,
            &context.case_source,
        )
    }
    .unwrap();
    let mut primary = layout.clone();
    primary.run_root = layout
        .run_root
        .join("focused")
        .join(super::support::api_directory("GET /api"));
    primary.active_dir = primary.run_root.join(".active");
    primary.latest_dir = primary.run_root.join("latest");
    fs::create_dir_all(primary.active_dir.join("reports")).unwrap();
    let mut state = ActiveRunState::new(layout.run_key.clone(), 1, &inventory, &primary.active_dir);
    state.status = RunStatus::Failed;
    state.finished_at = Some(chrono::Utc::now());
    state.session_id = Some("session".into());
    state.replay_finalized = true;
    for case in &mut state.cases {
        case.status = CaseStatus::Failed;
        case.assertion_passed = Some(true);
        case.replay_clean = Some(false);
    }
    store::write_json(&state.replay_report, &report).unwrap();
    super::final_evidence::build_final_evidence(&config, &primary, &inventory, &mut state).unwrap();
    let mut index =
        RunIndex::empty_managed(layout.run_key.clone(), layout.case_source.clone(), root).unwrap();
    if unprepared_api {
        crate::verification_progress::record_completed_batch(
            &layout.progress_path,
            &layout.run_key,
            chrono::Utc::now().to_rfc3339(),
            std::collections::BTreeMap::from([
                ("GET /api".into(), 1),
                ("OPTIONS /api".into(), 1),
                ("GET /unprepared".into(), 1),
            ]),
        )
        .unwrap();
    }
    super::progress::update_focused_index(&mut index, &state, &inventory, !unprepared_api);
    super::progress::write_replay_progress(
        &layout.progress_path,
        &layout.legacy_progress_path,
        &index,
        &state,
    )
    .unwrap();
    super::focused_batch::publish(&layout, &primary, &state).unwrap();
    store::write_yaml(&layout.index_path, &index).unwrap();
    context
}

pub(crate) fn state_path(context: &super::E2eRunContext, api: &str) -> std::path::PathBuf {
    let (_, layout) =
        super::config::resolve_layout(&context.target_root, &context.case_source, None).unwrap();
    layout
        .run_root
        .join("focused")
        .join(super::support::api_directory(api))
        .join("latest/state.yaml")
}

pub(crate) fn classify_stream(root: &Path) {
    let policy = json!({"format":"traffic-policy/v2","rules":[{
        "id":"stream-startup","match":{},"effect":{"kind":"process_owned","source_revision":"",
            "selector":{"protocol":"http","authorities":["stream.test"],"methods":["GET"],"path_prefixes":["/connect"]}},
        "proof":{"source":"startup.rs:1","fact":"Source starts this process-wide stream independently of API calls"}
    }]});
    crate::policy::compile_policy(&serde_json::from_value(policy.clone()).unwrap()).unwrap();
    fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        serde_yaml::to_string(&policy).unwrap(),
    )
    .unwrap();
}

pub(super) fn config(root: &Path) -> ResolvedProjectConfig {
    ResolvedProjectConfig {
        replay_case_no_progress_timeout: Duration::from_secs(5),
        replay_pre_match: true,
        replay_http_stream_timing: Default::default(),
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

/// Reproduce the old one-method overlay without publishing the sibling snapshot.
pub(crate) fn legacy_split(context: &super::E2eRunContext) -> (PathBuf, PathBuf) {
    let (config, layout) =
        super::config::resolve_layout(&context.target_root, &context.case_source, None).unwrap();
    let inventory =
        crate::case_group::load_case_group_inventory(&layout.group_index_path, &layout.case_source)
            .unwrap();
    let primary: ActiveRunState = store::read_yaml(&state_path(context, "GET /api")).unwrap();
    super::final_evidence::refresh_background_evidence(&config, &primary, &inventory).unwrap();
    let sibling: ActiveRunState = store::read_yaml(&state_path(context, "OPTIONS /api")).unwrap();
    (sibling.replay_report, layout.progress_path)
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
        "version":6,"case_dir":source,"session_id":"session","started_at":"2026-10-12T00:00:00Z",
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
