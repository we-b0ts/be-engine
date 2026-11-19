use super::*;
use crate::protocols::recording::events::{DependencyConnectFailureEvent, RecorderEvent};
use crate::recorder::Recorder;
use serde_json::{Value, json};

async fn recording() -> (tempfile::TempDir, Recorder) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("periodic-task-selector".into(), "periodic_task".into());
    let recorder = Recorder::new(temp.path().join("recordings"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    recorder
        .observe_accessed_endpoint("cache.test", 6379)
        .await
        .unwrap();
    recorder
        .append_global_dependency(
            &RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
                id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                client_addr: None,
                protocol: "redis".into(),
                target_host: "cache.test".into(),
                target_port: 6379,
                duration_ms: 0,
                failure_kind: "connection_refused".into(),
                client_outcome: "reset".into(),
            }),
            "background_rule",
            "runtime",
            "periodic-task-selector",
        )
        .await
        .unwrap();
    super::super::super::test_support::recording::publish_case(&recorder).await;
    recorder.finish_run().await.unwrap();
    (temp, recorder)
}

#[tokio::test]
async fn real_process_connection_failure_cannot_certify_a_complete_session() {
    let (_temp, recorder) = recording().await;
    let root = recorder.run_dir().as_ref();
    let (_, manifest) = recording::manifest(root).unwrap();
    assert_eq!(
        manifest.semantic_inventory.unsupported_by_scope["process"]["dependency_connect_failure"],
        1
    );
    let addr = "127.0.0.1:0".parse().unwrap();
    let report = root.parent().unwrap().join("report/replay.json");
    let runtime = ReplayRuntime::load(
        ReplayConfig {
            case_dir: root.into(),
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(report.clone()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: None,
            ca_key_path: None,
            policy_path: None,
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap();
    let id = manifest.inputs[0].case_id;
    for command in ["begin", "request_begin", "end", "finalize"] {
        let request = serde_json::from_value(json!({"command":command,"case_id":id,
            "fail_on_dirty":false,"fail_on_incomplete":false}))
        .unwrap();
        let (response, _) = crate::replay::control::handle_control_request(
            request,
            runtime.state.clone(),
            Some(report.clone()),
            None,
        )
        .await;
        assert_eq!(response["ok"], true, "{command}: {response}");
    }
    let actual: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(actual["complete"], true);
    assert_eq!(actual["finalized"], true);
    assert_eq!(
        actual["batch_reconciliation"]["dependency_inventory_verified"],
        false
    );
    assert!(crate::adapters::report::validation::validate_completed_receipt(&actual).is_err());
}

#[tokio::test]
async fn unlocated_inventory_gaps_block_local_acceptance_while_known_run_debt_stays_separate() {
    let (_temp, recorder) = recording().await;
    let root = recorder.run_dir().as_ref();
    let (manifest_root, mut manifest) = recording::manifest(root).unwrap();
    let case = root.join(&manifest.inputs[0].path);
    let load = |suffix: &str| {
        let addr = "127.0.0.1:0".parse().unwrap();
        ReplayRuntime::load(
            ReplayConfig {
                case_dir: case.clone(),
                selected_case_ids: vec![],
                dns_listen: addr,
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: Some(root.parent().unwrap().join(format!("{suffix}/report.json"))),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: None,
                ca_key_path: None,
                policy_path: None,
                http_ignore_query_params: vec![],
                process_owned_dependencies: vec![],
                allowed_unused_http: None,
            },
            addr,
            addr,
        )
    };
    let runtime = load("known-debt").await.unwrap();
    let report = runtime.state.lock().await.snapshot_report();
    assert!(
        !report.is_dirty(),
        "a separately known process failure must not fabricate a Case failure"
    );
    assert!(
        !report
            .batch_reconciliation
            .unwrap()
            .dependency_inventory_verified
    );
    manifest.coverage.inventory_gaps = true;
    manifest.capture_complete = false;
    std::fs::write(
        manifest_root.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let runtime = load("unlocated-gap").await.unwrap();
    let report = runtime.state.lock().await.snapshot_report();
    assert!(report.is_dirty());
    assert!(
        report
            .case_execution_failures
            .iter()
            .any(|failure| failure["kind"] == "source_inventory_gap")
    );
}

#[tokio::test]
async fn source_metadata_rebuild_recovers_missing_unsupported_markers_and_case_overlay_support() {
    let (_temp, recorder) = recording().await;
    let root = recorder.run_dir().as_ref();
    let (_, mut manifest) = recording::manifest(root).unwrap();
    // The central facts remain authoritative even for a current-schema manual
    // manifest which omitted a compact unsupported marker.
    manifest.semantic_inventory.unsupported_by_scope.clear();
    let inventory = effective(root, &manifest, &BTreeMap::new()).unwrap();
    assert_eq!(
        inventory.unsupported_by_scope["process"]["dependency_connect_failure"],
        1
    );
    let index = crate::dependency_index::load_file(&root.join("dependencies.jsonl")).unwrap();
    let exchange = index.proof_records.as_ref().unwrap()[0].selector["capture"]["exchange_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let decision = crate::dependency::attribution::AttributionDecision {
        exchange_id: exchange,
        owner: DependencyOwner::Case {
            origin_case_id: manifest.inputs[0].case_id,
            task_instance: None,
        },
        proof_id: "independent-proof".into(),
        proof_revision: 1,
        rule_bindings: Default::default(),
        proof: crate::dependency::attribution::AttributionProof {
            source_revision: "source".into(),
            source_locations: vec!["source.rs:1".into()],
            call_chain: "primary starts the connection".into(),
            exclusive_scope: "one primary invocation".into(),
        },
    };
    let attributed = effective(
        root,
        &manifest,
        &BTreeMap::from([(decision.exchange_id, decision.owner)]),
    )
    .unwrap();
    assert_eq!(attributed.by_owner_kind["case"], 1);
    assert!(attributed.unsupported_by_scope.is_empty());
}

#[tokio::test]
async fn an_omitted_or_repeated_scope_location_cannot_hide_a_mandatory_fact() {
    let (_temp, recorder) = recording().await;
    let root = recorder.run_dir().as_ref();
    let (_, manifest) = recording::manifest(root).unwrap();
    let path = root.join("indexes/process-scope.json");
    let mut scope: ScopeIndex = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let original = scope.locations.clone();
    for locations in [vec![], vec![original[0].clone(), original[0].clone()]] {
        scope.locations = locations;
        std::fs::write(&path, serde_json::to_vec(&scope).unwrap()).unwrap();
        assert!(effective(root, &manifest, &BTreeMap::new()).is_err());
    }
}

#[tokio::test]
async fn mandatory_closure_does_not_materialize_a_second_complete_payload_selector_index() {
    let (_temp, recorder) = recording().await;
    let root = recorder.run_dir().as_ref();
    let (_, manifest) = recording::manifest(root).unwrap();
    let full_index =
        crate::dependency_index::store::cache_directory(&root.join("dependencies.jsonl"))
            .join("file.json");
    assert!(!full_index.exists());
    let inventory = effective(root, &manifest, &BTreeMap::new()).unwrap();
    assert_eq!(
        inventory.total_mandatory,
        manifest.semantic_inventory.total_mandatory
    );
    assert!(!full_index.exists());
}

#[tokio::test]
async fn associated_shutdown_has_authenticated_scope_without_entering_primary_inventory() {
    use crate::protocols::recording::events::HttpExchangeEvent;
    use crate::recorder::{CaseContext, capture_body};
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.http_gateway.enabled = false;
    let app = crate::AppState::new(config).await.unwrap();
    crate::test_support::close_bootstrap(&app, "ready")
        .await
        .unwrap();
    let case = CaseContext {
        id: Uuid::from_u128(123),
        rule_name: "fixture".into(),
        uri_group: None,
    };
    let guard = crate::test_support::reserve_active_case(&app, case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    crate::test_support::close_admission(&app);
    super::super::super::test_support::recording::publish_case(app.recorder()).await;
    drop(guard);
    let id = Uuid::new_v4();
    crate::test_support::record_dependency(
        &app,
        ProtocolRef::exchange("http", id),
        RecorderEvent::HttpExchange(HttpExchangeEvent {
            outcome: crate::DependencyExchangeOutcome::Response,
            id,
            timestamp: chrono::Utc::now(),
            request_started_at: chrono::Utc::now(),
            client_addr: None,
            upstream_addr: None,
            scheme: "http".into(),
            method: "GET".into(),
            uri: "/cleanup".into(),
            authority: Some("worker.test:80".into()),
            request_headers: Default::default(),
            request_body: capture_body(b"", 16),
            response_status: Some(200),
            response_headers: Some(Default::default()),
            response_body: Some(capture_body(b"done", 16)),
            response_stream: None,
            discovered_tcp_targets: vec![],
            duration_ms: 1,
            error: None,
        }),
    );
    app.recorder().finish_run().await.unwrap();
    let root = app.recorder().run_dir().as_ref();
    let (_, manifest) = recording::manifest(root).unwrap();
    assert!(manifest.capture_complete);
    let inventory = effective(root, &manifest, &BTreeMap::new()).unwrap();
    assert_eq!(inventory.total_mandatory, 1);
    assert_eq!(inventory.by_owner_kind["shutdown"], 1);
    assert_eq!(inventory.unattributed_dependencies, 0);
    assert!(inventory.unsupported_by_scope.is_empty());
    let primary: ScopeIndex = serde_json::from_slice(
        &std::fs::read(
            root.join(&manifest.inputs[0].path)
                .join("dependency-scope.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(primary.locations.is_empty());
    assert!(
        manifest
            .files
            .iter()
            .any(|file| file.path == "indexes/shutdown-scope.json")
    );
}
