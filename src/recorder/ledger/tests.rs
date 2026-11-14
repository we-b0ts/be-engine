//! Real writer completion proves central inventory independently of traffic logs.
use super::*;
use crate::config::TrafficJsonlMode;
use crate::dependency::observation::{ProtocolRef, RecordingManifest, ScopeIndex};
use crate::recorder::{CaseContext, DependencyConnectFailureEvent, RecorderEvent};
use crate::{AppConfig, AppState};
use std::time::Duration;

mod custom_protocol;
mod shutdown;

fn failure() -> RecorderEvent {
    RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        client_addr: None,
        protocol: "redis".into(),
        target_host: "cache.test".into(),
        target_port: 6379,
        duration_ms: 1,
        failure_kind: "connection_refused".into(),
        client_outcome: "reset".into(),
    })
}

async fn state() -> (tempfile::TempDir, AppState) {
    state_with_providers(crate::protocols::default_providers()).await
}

async fn state_with_providers(
    providers: Arc<crate::protocols::DependencyProviders>,
) -> (tempfile::TempDir, AppState) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = AppConfig::default();
    config
        .process_dependency_tasks
        .insert("periodic-cache-refresh".into(), "cache_refresh".into());
    config.recording.output_dir = temp.path().join("recordings");
    config.recording.traffic_jsonl = TrafficJsonlMode::Off;
    config.http_gateway.enabled = false;
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new_with_providers(config, providers)
        .await
        .unwrap();
    state
        .close_bootstrap("test initialization completed")
        .await
        .unwrap();
    (temp, state)
}

fn start(state: &AppState) -> crate::active_case::DependencyTargets {
    state.capture_dependency_start(ProtocolRef::observation(Uuid::new_v4(), "connect_attempt"))
}

async fn records(state: &AppState) -> Vec<serde_json::Value> {
    let raw = crate::recorder::test_io::read_to_string(
        state.recorder().run_dir.join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    raw.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn admission_sequences_survive_reverse_completion_in_the_real_writer() {
    let (_temp, state) = state().await;
    let first = start(&state);
    let second = start(&state);
    state.record_event_for_targets(failure(), second);
    state.record_event_for_targets(failure(), first);
    state.recorder().finish_run().await.unwrap();

    let rows = records(&state).await;
    assert_eq!(rows[0]["capture"]["sequence"], 2);
    assert_eq!(rows[1]["capture"]["sequence"], 1);
    let raw =
        tokio::fs::read_to_string(state.recorder().run_dir.join("dependency-lifecycle.jsonl"))
            .await
            .unwrap();
    let events = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    let mut sequences = events
        .iter()
        .map(|event| event["sequence"].as_u64().unwrap())
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=events.len() as u64).collect::<Vec<_>>());
    assert!(events.iter().all(|event| event["offset_micros"].is_u64()));
    let admitted = events
        .iter()
        .filter(|event| event["event_type"] == "capture_started")
        .map(|event| event["dependency_sequence"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(admitted, [1, 2]);
}

#[tokio::test]
async fn unattributed_requests_survive_disabled_traffic_and_have_unique_terminal_receipts() {
    let (_temp, state) = state().await;
    state.record_event_for_targets(failure(), start(&state));
    state.recorder().finish_run().await.unwrap();
    let rows = records(&state).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["capture"]["attribution"]["kind"], "unattributed");
    assert_eq!(rows[0]["capture"]["phase"], "runtime");
    let root = &state.recorder().run_dir;
    assert!(!root.join("traffic.jsonl").exists());
    let scope: ScopeIndex = serde_json::from_slice(
        &tokio::fs::read(root.join("indexes/unattributed-scope.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(scope.locations.len(), 1);
    let manifest: RecordingManifest = serde_json::from_slice(
        &tokio::fs::read(root.join("dependency-manifest.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(manifest.capture_complete);
    assert!(manifest.capture_policy_identity.starts_with("sha256:"));
    assert!(matches!(
        manifest.source_artifact,
        crate::dependency::observation::SourceArtifactIdentity::Unavailable { .. }
    ));
    assert_eq!(manifest.coverage.admitted, 1);
    assert_eq!(manifest.coverage.terminal, 1);
    assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
    assert_eq!(manifest.semantic_inventory.unattributed_dependencies, 1);
    assert_eq!(manifest.semantic_inventory.by_owner_kind["unattributed"], 1);
    assert_eq!(
        manifest.semantic_inventory.unsupported_by_scope["unattributed"]["dependency_connect_failure"],
        1
    );
    assert!(
        manifest
            .files
            .iter()
            .any(|f| f.path == "indexes/unattributed-scope.json")
    );
}

#[tokio::test]
async fn start_ownership_and_closed_case_observation_are_separate() {
    let (_temp, state) = state().await;
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "case".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let accepted = start(&state);
    let registry = state.inner.active_cases.clone();
    let id = case.id;
    let drain = tokio::spawn(async move {
        registry
            .drain_case_dependencies(id, Duration::ZERO, Duration::from_secs(2))
            .await
    });
    tokio::task::yield_now().await;
    let after_close = start(&state);
    assert_eq!(after_close.observed_case, Some(case.id));
    assert!(after_close.cases.is_empty());
    state.record_event_for_targets(failure(), after_close);
    state.record_event_for_targets(failure(), accepted);
    assert_eq!(
        drain.await.unwrap(),
        crate::active_case::DependencyDrainResult::Drained
    );
    state
        .recorder()
        .flush_case_dependency_files(&state.recorder().case_staging_dir(&case))
        .await
        .unwrap();
    drop(guard);
    state.recorder().finish_run().await.unwrap();
    let rows = records(&state).await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|v| v["capture"]["attribution"]["kind"] == "unattributed"
                && v["capture"]["observed_case"] == case.id.to_string())
    );
    assert!(
        rows.iter()
            .any(|v| v["capture"]["attribution"]["origin_case_id"] == case.id.to_string())
    );
}

#[tokio::test]
async fn process_ownership_cannot_release_the_run_capture_barrier() {
    let (_temp, state) = state().await;
    let request = start(&state).into_process_owned("periodic-cache-refresh".into());
    state.recorder().capture.close();
    assert!(
        !state
            .recorder()
            .capture
            .drain(Duration::from_millis(1))
            .await
    );
    state.record_event_for_targets(failure(), request);
    assert!(state.recorder().capture.drain(Duration::from_secs(1)).await);
    state.recorder().finish_run().await.unwrap();
    assert_eq!(
        records(&state).await[0]["capture"]["attribution"]["kind"],
        "process"
    );
}

#[tokio::test]
async fn abandoned_capture_is_sealed_as_incomplete_instead_of_disappearing() {
    let (_temp, state) = state().await;
    drop(start(&state));
    state.recorder().finish_run().await.unwrap();
    let manifest: RecordingManifest = serde_json::from_slice(
        &tokio::fs::read(state.recorder().run_dir.join("dependency-manifest.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!manifest.capture_complete);
    assert_eq!(manifest.coverage.admitted, 1);
    assert_eq!(manifest.coverage.terminal, 1);
    assert_eq!(manifest.coverage.capture_failures, 1);
}

#[tokio::test]
async fn a_published_scope_can_be_read_while_unrelated_run_records_are_appended() {
    let (_temp, state) = state().await;
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "fixed-scope".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    state.record_event_for_targets(failure(), start(&state));
    state.drain_active_case_dependencies(case.id).await;
    let directory = state.recorder().case_staging_dir(&case);
    state
        .recorder()
        .flush_case_dependency_files(&directory)
        .await
        .unwrap();
    let mut stream =
        crate::dependency_index::RecordStream::open(&directory.join("dependencies.jsonl")).unwrap();
    state.record_event_for_targets(failure(), start(&state));
    state.recorder().flush_all_dependency_files().await.unwrap();
    let (_, line) = stream.next().unwrap().unwrap();
    let row: serde_json::Value = serde_json::from_slice(line).unwrap();
    assert_eq!(
        row["capture"]["attribution"]["origin_case_id"],
        case.id.to_string()
    );
    assert!(stream.next().unwrap().is_none());
    drop(guard);
}

#[tokio::test]
async fn sealing_twice_and_late_facts_cannot_mutate_the_authenticated_ledger() {
    let (_temp, state) = state().await;
    state.record_event_for_targets(failure(), start(&state));
    state.recorder().finish_run().await.unwrap();
    let root = &state.recorder().run_dir;
    let payload = tokio::fs::read(root.join("dependencies.jsonl"))
        .await
        .unwrap();
    let lifecycle = tokio::fs::read(root.join("dependency-lifecycle.jsonl"))
        .await
        .unwrap();
    state.recorder().finish_run().await.unwrap();
    assert_eq!(
        tokio::fs::read(root.join("dependency-lifecycle.jsonl"))
            .await
            .unwrap(),
        lifecycle
    );
    state.record_event_for_targets(failure(), start(&state));
    assert!(state.recorder().flush_traffic().await.is_err());
    assert_eq!(
        tokio::fs::read(root.join("dependencies.jsonl"))
            .await
            .unwrap(),
        payload
    );
    assert_eq!(
        tokio::fs::read(root.join("dependency-lifecycle.jsonl"))
            .await
            .unwrap(),
        lifecycle
    );
}

#[tokio::test]
async fn writer_shutdown_does_not_rewrite_sealed_scope_files() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = crate::recorder::Recorder::new(temp.path()).await.unwrap();
    recorder
        .append_global_dependency(
            &failure(),
            "bootstrap_window",
            "bootstrap",
            "bootstrap_window",
        )
        .await
        .unwrap();
    recorder.finish_run().await.unwrap();
    let completion = recorder.writer.completion.clone();
    let scopes = ["startup", "process", "unattributed"]
        .map(|name| recorder.run_dir.join(format!("indexes/{name}-scope.json")));
    let stamps = scopes
        .each_ref()
        .map(|path| crate::dependency_index::FileStamp::read_native(path).unwrap());
    drop(recorder);
    tokio::time::timeout(Duration::from_secs(1), completion.notified())
        .await
        .unwrap();
    for (path, expected) in scopes.iter().zip(stamps) {
        assert_eq!(
            crate::dependency_index::FileStamp::read_native(path).unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn actual_overlapping_http_selectors_require_a_unique_source_task() {
    for other_task in ["refresh", "cleanup"] {
        let temp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        config.http_gateway.enabled = false;
        for (id, path, task) in [
            ("rule-a", "/task", "refresh"),
            ("rule-b", "/task/step", other_task),
        ] {
            config
                .process_dependency_tasks
                .insert(id.into(), task.into());
            config
                .process_owned_dependencies
                .push(crate::BackgroundDependencyRuleConfig::Http {
                    name: id.into(),
                    authorities: vec!["worker.test".into()],
                    methods: vec!["GET".into()],
                    path_prefixes: vec![path.into()],
                    source_revision: "abcdef1".into(),
                    source_evidence: "Worker.java:42".into(),
                });
        }
        let state = AppState::new(config).await.unwrap();
        state
            .close_bootstrap("actual Source initialization ended")
            .await
            .unwrap();
        let targets = state.capture_http_dependency_request(
            &hyper::Method::GET,
            &"http://worker.test/task/step".parse().unwrap(),
            Some("worker.test"),
        );
        state.record_event_for_targets(
            RecorderEvent::HttpExchange(crate::recorder::HttpExchangeEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                request_started_at: Utc::now(),
                client_addr: None,
                scheme: "http".into(),
                method: "GET".into(),
                uri: "/task/step".into(),
                authority: Some("worker.test".into()),
                request_headers: Default::default(),
                request_body: crate::recorder::capture_body(b"", 1024),
                response_status: Some(200),
                response_headers: Some(Default::default()),
                response_body: Some(crate::recorder::capture_body(b"ok", 1024)),
                response_stream: None,
                discovered_tcp_targets: Vec::new(),
                duration_ms: 1,
                error: None,
                outcome: crate::DependencyExchangeOutcome::Response,
            }),
            targets,
        );
        state.recorder().finish_run().await.unwrap();
        let row = &records(&state).await[0];
        assert_eq!(row["capture"]["phase"], "runtime");
        assert_eq!(
            row["capture"]["matched_rule_ids"].as_array().unwrap().len(),
            2
        );
        if other_task == "refresh" {
            assert_eq!(row["capture"]["attribution"]["kind"], "process");
            assert_eq!(row["capture"]["attribution"]["source_task"], "refresh");
        } else {
            assert_eq!(row["capture"]["attribution"]["kind"], "unattributed");
            assert_eq!(
                row["capture"]["attribution"]["reason"],
                "ambiguous_process_task"
            );
        }
    }
}

#[tokio::test]
async fn runtime_initialization_labels_do_not_invent_a_restart_phase() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = crate::recorder::Recorder::new(temp.path()).await.unwrap();
    recorder
        .append_global_dependency(&failure(), "bootstrap_window", "runtime", "lazy_init")
        .await
        .unwrap();
    recorder.finish_run().await.unwrap();
    let raw = tokio::fs::read_to_string(recorder.run_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    let row: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(row["capture"]["phase"], "runtime");
    assert_eq!(row["capture"]["attribution"]["kind"], "unattributed");
}

#[tokio::test]
async fn compact_semantic_inventory_counts_unsupported_case_effects_without_counting_control() {
    let (_temp, state) = state().await;
    state.record_event(RecorderEvent::ProxyError(
        crate::recorder::ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: None,
            timestamp: Utc::now(),
            protocol: "test_control".into(),
            client_addr: None,
            target: None,
            error: "control capture failure".into(),
        },
    ));
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "udp-input".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    state.record_event_for_targets(
        RecorderEvent::UdpDatagram(crate::recorder::UdpDatagramEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            listen_addr: "127.0.0.1:4002".into(),
            client_addr: None,
            target_host: Some("udp.test".into()),
            target_port: Some(53),
            target_addr: None,
            fake_addr: None,
            upstream_addr: None,
            protocol: "udp".into(),
            forwarded: true,
            payload: crate::recorder::capture_body(b"request", 1024),
            payload_text: None,
            duration_ms: 1,
            error: None,
        }),
        start(&state),
    );
    drop(guard);
    state.recorder().finish_run().await.unwrap();
    let manifest: RecordingManifest = serde_json::from_slice(
        &tokio::fs::read(state.recorder().run_dir.join("dependency-manifest.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
    assert_eq!(manifest.semantic_inventory.by_owner_kind["case"], 1);
    assert_eq!(manifest.unattributed_records, 1);
    assert_eq!(manifest.semantic_inventory.unattributed_dependencies, 0);
    assert_eq!(
        manifest.semantic_inventory.unsupported_by_scope[&case.id.to_string()]["udp_datagram"],
        1
    );
}

#[tokio::test]
async fn unparsed_tcp_payload_remains_a_mandatory_unsupported_obligation() {
    let (_temp, state) = state().await;
    state.record_event_for_targets(
        RecorderEvent::TcpGatewayConnection(crate::recorder::TcpGatewayConnectionEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            client_addr: None,
            domain: Some("opaque.test".into()),
            fake_addr: "198.18.0.1:9000".into(),
            upstream_addr: Some("127.0.0.1:9000".into()),
            client_to_server_bytes: 1,
            server_to_client_bytes: 2,
            duration_ms: 0,
            error: None,
        }),
        start(&state),
    );
    state.recorder().finish_run().await.unwrap();
    let root = &state.recorder().run_dir;
    let manifest: RecordingManifest = serde_json::from_slice(
        &tokio::fs::read(root.join("dependency-manifest.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.semantic_inventory.total_mandatory, 1);
    assert_eq!(
        manifest.semantic_inventory.unsupported_by_scope["unattributed"]["tcp_gateway_connection"],
        1
    );
    assert_eq!(
        records(&state).await[0]["capture"]["semantic_required"],
        true
    );
}
