use super::*;
use crate::replay::test_support::recording as fixtures;
use crate::replay::{ReplayConfig, ReplayRuntime};
use fixtures::case_path;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::MetadataExt;

fn capture(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false})
}
fn records() -> Vec<Value> {
    let connection = uuid::Uuid::from_u128(7);
    vec![
        json!({"event_type":"redis_exchange","connection_id":connection,"sequence":1,
            "target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
            "command":"GET","args":[capture("key")],"response":capture("$5\r\nvalue\r\n"),
            "response_kind":"bulk_string","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"redis_exchange","connection_id":connection,"sequence":2,
            "target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
            "command":"SUBSCRIBE","args":[capture("jobs")],"response":capture("*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n"),
            "response_kind":"array","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"redis_pub_sub_push","connection_id":connection,"subscription_sequence":2,
            "target_host":"redis.test","target_port":6379,"database":0,
            "response":capture("*3\r\n$7\r\nmessage\r\n$4\r\njobs\r\n$4\r\nbody\r\n"),
            "duration_ms":0,"replay_safe":true}),
    ]
}

fn noop_commit() -> Value {
    json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::from_u128(9),
        "query_sequence":1,"command":"COM_QUERY","sql":"COMMIT",
        "target_host":"db.test","target_port":3306,"database":"app","username":"reader",
        "server_status_before":2,"outcome":"response","parse_warnings":[],
        "response":{"status":"ok","server_status":2,"affected_rows":0,"last_insert_id":0,
            "columns":[],"rows":[],"rows_truncated":false}})
}

async fn recorded(
    temp: &Path,
    values: &[Value],
) -> (
    crate::recorder::Recorder,
    crate::AppConfig,
    std::path::PathBuf,
) {
    let owner = temp.join(".traffic-e2e");
    fs::create_dir_all(&owner).unwrap();
    let policy = owner.join("policy.yaml");
    fs::write(
        &policy,
        crate::config::SourceTrafficPolicyConfig::empty()
            .render()
            .unwrap(),
    )
    .unwrap();
    let project = owner.join("project.yaml");
    fs::write(&project, "version: 18\nproject:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  dns_mock: {enabled: true}\n  tcp_gateway: {enabled: true, record_http: true}\n").unwrap();
    let config = crate::AppConfig::load(&project).unwrap();
    let recorder = crate::recorder::Recorder::new(owner.join("local/recordings"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    for value in values {
        fixtures::append(&recorder, value, false).await;
    }
    fixtures::publish_case(&recorder).await;
    (recorder, config, policy)
}

async fn load(
    run: &Path,
    policy: &Path,
    config: &crate::AppConfig,
    report: &Path,
) -> ReplayRuntime {
    let case = case_path(run);
    let addr = "127.0.0.1:0".parse().unwrap();
    ReplayRuntime::load(
        ReplayConfig {
            case_dir: case,
            selected_case_ids: vec![],
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: Some(report.into()),
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(run.join("test-ca.pem")),
            ca_key_path: Some(run.join("test-ca-key.pem")),
            policy_path: Some(policy.into()),
            http_ignore_query_params: vec![],
            process_owned_dependencies: config.process_owned_dependencies.clone(),
            allowed_unused_http: None,
        },
        addr,
        addr,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn recorder_prewarms_the_exact_replay_policy_layout_and_notification_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(temp.path(), &records()).await;
    assert!(!recorder.finish_run().await.unwrap());
    let marker = recorder.run_dir.join(MARKER);
    let status: Preparation = store::read_json(&marker).unwrap();
    assert_eq!(status.status, "ready", "{:?}", status.reason);
    assert_eq!(
        status.policy,
        policy_identity(
            &config.process_owned_dependencies,
            config.global_projection_policy.as_deref()
        )
        .unwrap()
    );
    assert!(
        recorder
            .run_dir
            .join(crate::dependency_index::global::GLOBAL_FRAGMENT)
            .is_file()
    );
    assert!(!recorder.run_dir.join(".replay/replay-ca.pem").exists());
    assert!(status.notifications.is_some());
    let report = temp
        .path()
        .join(".traffic-e2e/local/artifacts/replays/first/report.json");
    let runtime = load(&recorder.run_dir, &policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let fingerprint = state.replay_policy.as_ref().unwrap().report().fingerprint;
    assert_eq!(
        Some(&fingerprint),
        config.global_projection_policy.as_ref(),
        "Source facts must not alter compiled policy identity"
    );
    let runtime_identity =
        policy_identity(&config.process_owned_dependencies, Some(&fingerprint)).unwrap();
    for protocol in super::super::PROTOCOLS {
        let evidence = super::super::regular::RegularEvidence::prepare(&report, &state, protocol)
            .unwrap()
            .unwrap();
        let reference: ArtifactReference =
            serde_json::from_value(serde_json::to_value(evidence).unwrap()["inventory"].clone())
                .unwrap();
        let (inventory, destination) = reference.load::<Inventory>(&report).unwrap();
        let expected = Identity {
            source_sha256: status.source_sha256.clone().unwrap(),
            source_bytes: crate::dependency_index::FileStamp::read(
                &recorder.run_dir.join("global-dependencies.jsonl"),
            )
            .unwrap()
            .size,
            policy: runtime_identity.clone(),
            protocol: protocol.into(),
            layout: crate::replay::global_source::ProjectionView::from(&*state)
                .layout(protocol)
                .unwrap(),
            semantics: Identity::current_semantics(protocol),
        };
        assert_eq!(inventory.identity, expected);
        assert_eq!(reference.key(), status.inventories[protocol].key());
        if !inventory.pages.is_empty() {
            let (_, original) = status.inventories[protocol]
                .load::<Inventory>(&marker)
                .unwrap();
            assert_eq!(
                fs::metadata(original.join("0.json")).unwrap().ino(),
                fs::metadata(destination.join("0.json")).unwrap().ino(),
                "first Replay imports recorded pages instead of visiting and serializing all rows again"
            );
        }
        super::super::regular::retain_reference(
            &report,
            expected,
            false,
            Some(&recorder.run_dir.join("global-dependencies.jsonl")),
            |_| panic!("warm projection must not visit native rows"),
        )
        .unwrap();
    }
    let session = state.redis.global_notification_evidence().unwrap();
    let notifications = super::super::shared::retain(&report, &session.lanes).unwrap();
    assert_eq!(
        notifications.key(),
        status.notifications.as_ref().unwrap().key()
    );
    drop(state);
    // Local durable inventories no longer depend on the optional portable copy.
    fs::remove_dir_all(recorder.run_dir.join(".replay/shared-global-inventories")).unwrap();
    load(
        &recorder.run_dir,
        &policy,
        &config,
        &temp
            .path()
            .join(".traffic-e2e/local/artifacts/replays/second/report.json"),
    )
    .await;
}

#[tokio::test]
async fn mysql_cleanup_prewarm_imports_the_current_hidden_noop_commit_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(temp.path(), &[noop_commit()]).await;
    recorder.finish_run().await.unwrap();
    let marker = recorder.run_dir.join(MARKER);
    let status: Preparation = store::read_json(&marker).unwrap();
    assert_eq!(status.status, "ready", "{:?}", status.reason);
    let (portable, original) = status.inventories["mysql"]
        .load::<Inventory>(&marker)
        .unwrap();
    assert_eq!(portable.recorded, 1);
    assert_eq!(portable.visible, 0);
    assert_eq!(
        portable.identity.semantics.as_deref(),
        Some("mysql-transaction-diagnostics-v6-source-read-proof")
    );
    let report = temp
        .path()
        .join(".traffic-e2e/local/artifacts/replays/mysql/report.json");
    let runtime = load(&recorder.run_dir, &policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let evidence = super::super::regular::RegularEvidence::prepare(&report, &state, "mysql")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.count().unwrap(), 0);
    let reference: ArtifactReference =
        serde_json::from_value(serde_json::to_value(evidence).unwrap()["inventory"].clone())
            .unwrap();
    assert_eq!(reference.key(), status.inventories["mysql"].key());
    let (imported, destination) = reference.load::<Inventory>(&report).unwrap();
    assert_eq!(imported.identity, portable.identity);
    assert_eq!(
        fs::metadata(original.join("0.json")).unwrap().ino(),
        fs::metadata(destination.join("0.json")).unwrap().ino(),
        "new MySQL semantics use the recording's portable pages"
    );
}

#[tokio::test]
async fn historical_mysql_prewarm_is_skipped_without_invalidating_other_protocols() {
    for semantics in [
        None,
        Some("mysql-transaction-diagnostics-v4".to_owned()),
        Some("mysql-transaction-diagnostics-v5-first-write-through-end".to_owned()),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (recorder, _, _) = recorded(temp.path(), &[noop_commit()]).await;
        recorder.finish_run().await.unwrap();
        let marker = recorder.run_dir.join(MARKER);
        let mut status: Preparation = store::read_json(&marker).unwrap();
        assert_eq!(status.status, "ready");
        let (current, original) = status.inventories["mysql"]
            .load::<Inventory>(&marker)
            .unwrap();
        let mut historical = current.identity.clone();
        historical.semantics = semantics;
        let old =
            super::super::regular::retain_reference(&marker, historical, true, None, |visitor| {
                for page in 0..current.pages.len() {
                    for mut row in current.read_page(&original, page)? {
                        row.visible = true;
                        visitor(row)?;
                    }
                }
                Ok(())
            })
            .unwrap();
        status.inventories.insert("mysql".into(), old);
        store::write_json(&marker, &status).unwrap();
        let source = recorder.run_dir.join("global-dependencies.jsonl");
        let report = temp
            .path()
            .join(".traffic-e2e/local/artifacts/replays/import/report.json");
        assert!(
            import(&source, &report, &current.identity)
                .unwrap()
                .is_none()
        );
        let (redis, _) = status.inventories["redis"]
            .load::<Inventory>(&marker)
            .unwrap();
        assert!(redis.identity.semantics.is_none());
        assert!(import(&source, &report, &redis.identity).unwrap().is_some());
    }
}

#[tokio::test]
async fn missing_portable_inventory_rebuilds_but_published_pages_remain_strict() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(temp.path(), &records()).await;
    recorder.finish_run().await.unwrap();
    fs::remove_dir_all(recorder.run_dir.join(".replay/shared-global-inventories")).unwrap();
    let report = temp
        .path()
        .join(".traffic-e2e/local/artifacts/replays/fallback/report.json");
    let runtime = load(&recorder.run_dir, &policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let evidence = super::super::regular::RegularEvidence::prepare(&report, &state, "redis")
        .unwrap()
        .unwrap();
    let reference: ArtifactReference =
        serde_json::from_value(serde_json::to_value(&evidence).unwrap()["inventory"].clone())
            .unwrap();
    let (inventory, root) = reference.load::<Inventory>(&report).unwrap();
    assert!(!inventory.pages.is_empty());
    fs::write(root.join("0.json"), b"tampered").unwrap();
    assert!(
        evidence.read(&report, 0, 1, &mut vec![]).is_err(),
        "published evidence cannot silently rebuild damaged pages"
    );
}

#[tokio::test]
async fn unsupported_source_only_prewarm_preserves_recording_status_and_native_index() {
    let temp = tempfile::tempdir().unwrap();
    let mut unsafe_record = records().remove(0);
    unsafe_record["replay_safe"] = false.into();
    let (recorder, _, _) = recorded(temp.path(), &[unsafe_record.clone()]).await;
    assert!(!recorder.finish_run().await.unwrap());
    let status: Preparation = store::read_json(&recorder.run_dir.join(MARKER)).unwrap();
    assert_eq!(status.status, "prewarm_failed");
    assert!(status.reason.is_some());
    let report: Value =
        serde_json::from_slice(&fs::read(recorder.run_dir.join("recording-run.json")).unwrap())
            .unwrap();
    assert_eq!(report["status"], "completed");
    assert!(
        recorder
            .run_dir
            .join(crate::dependency_index::global::GLOBAL_FRAGMENT)
            .is_file()
    );
    let raw = crate::dependency_index::scoped::read_bytes(
        &recorder.run_dir.join("global-dependencies.jsonl"),
    )
    .unwrap();
    let retained: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(retained["replay_safe"], false);
    assert_eq!(retained["capture"]["attribution"]["kind"], "startup");
}

#[tokio::test]
async fn changed_policy_is_a_cold_projection_and_portable_indexes_survive_recording_move() {
    let origin = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(origin.path(), &records()).await;
    recorder.finish_run().await.unwrap();
    let marker = recorder.run_dir.join(MARKER);
    let status: Preparation = store::read_json(&marker).unwrap();
    assert_eq!(status.status, "ready");
    let (_, original_root) = status.inventories["redis"]
        .load::<Inventory>(&marker)
        .unwrap();
    let original_inode = fs::metadata(original_root.join("0.json")).unwrap().ino();
    let mut document = crate::policy::parse_policy(&fs::read_to_string(&policy).unwrap()).unwrap();
    document.rules.push(
        crate::policy::NativeRule {
            id: "additional-config".into(),
            selector: Default::default(),
            proof: None,
            when: None,
            effect: crate::policy::NativeEffect::ProcessOwned(
                crate::policy::native::ProcessOwnedEffect {
                    task_name: None,
                    source_revision: String::new(),
                    origin: None,
                    selector: crate::policy::native::ProcessSelector::Http {
                        authorities: vec!["additional-config.test".into()],
                        methods: vec!["GET".into()],
                        path_prefixes: vec!["/".into()],
                    },
                },
            ),
        }
        .into(),
    );
    fs::write(&policy, crate::policy::render_policy(&document).unwrap()).unwrap();
    let changed_config =
        crate::AppConfig::load(origin.path().join(".traffic-e2e/project.yaml")).unwrap();
    assert_ne!(
        config.global_projection_policy,
        changed_config.global_projection_policy
    );
    let changed_report = origin
        .path()
        .join(".traffic-e2e/local/artifacts/replays/changed/report.json");
    let changed = load(&recorder.run_dir, &policy, &changed_config, &changed_report).await;
    let state = changed.state.lock().await;
    let evidence =
        super::super::regular::RegularEvidence::prepare(&changed_report, &state, "redis")
            .unwrap()
            .unwrap();
    let reference: ArtifactReference =
        serde_json::from_value(serde_json::to_value(evidence).unwrap()["inventory"].clone())
            .unwrap();
    assert_ne!(reference.key(), status.inventories["redis"].key());
    let (_, changed_root) = reference.load::<Inventory>(&changed_report).unwrap();
    assert_ne!(
        fs::metadata(changed_root.join("0.json")).unwrap().ino(),
        original_inode
    );
    drop(state);

    // Carry a native Case index beside the native Global index and the optional
    // Source projections; none uses the old project's shared artifact anchor.
    let case = case_path(&recorder.run_dir);
    let native = crate::dependency_index::load_file(&case.join("dependencies.jsonl")).unwrap();
    store::write_json(&case.join(crate::dependency_index::FRAGMENT), &native).unwrap();
    let destination = tempfile::tempdir().unwrap();
    let run = destination
        .path()
        .join(".traffic-e2e/local/recordings/moved");
    copy_tree(&recorder.run_dir, &run);
    let moved_policy = destination.path().join(".traffic-e2e/policy.yaml");
    fs::write(&moved_policy, config_policy(&config)).unwrap();
    fs::remove_dir_all(origin.path().join(".traffic-e2e")).unwrap();
    assert!(
        run.join(crate::dependency_index::global::GLOBAL_FRAGMENT)
            .is_file()
    );
    assert!(
        case_path(&run)
            .join(crate::dependency_index::FRAGMENT)
            .is_file()
    );
    let report = destination
        .path()
        .join(".traffic-e2e/local/artifacts/replays/moved/report.json");
    let runtime = load(&run, &moved_policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let evidence = super::super::regular::RegularEvidence::prepare(&report, &state, "redis")
        .unwrap()
        .unwrap();
    let reference: ArtifactReference =
        serde_json::from_value(serde_json::to_value(&evidence).unwrap()["inventory"].clone())
            .unwrap();
    assert_eq!(reference.key(), status.inventories["redis"].key());
    let mut items = vec![];
    evidence.read(&report, 0, 10, &mut items).unwrap();
    assert_eq!(items.len(), 2);
}

fn config_policy(_config: &crate::AppConfig) -> String {
    crate::config::SourceTrafficPolicyConfig::empty()
        .render()
        .unwrap()
}
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let path = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &path);
        } else {
            fs::copy(entry.path(), path).unwrap();
        }
    }
}
