use super::*;
use crate::replay::test_support::recording as fixtures;
use crate::replay::{ReplayConfig, ReplayRuntime};
use fixtures::case_path;
use serde_json::{Value, json};
use std::fs;
use traffic_engine_replay::replay::report::global_evidence::{
    artifact::ArtifactReference,
    preparation::policy_identity,
    regular_store::{Identity, Inventory},
};
use traffic_replay::report::GlobalReportProjection;

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
    ]
}

async fn recorded(
    temp: &Path,
    values: &[Value],
) -> (
    traffic_engine_recording::recorder::Recorder,
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
    let recorder =
        traffic_engine_recording::recorder::Recorder::new(owner.join("local/recordings"))
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
async fn replay_prepares_the_exact_policy_layout_and_native_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(temp.path(), &records()).await;
    assert!(!recorder.finish_run().await.unwrap());
    let run = recorder.run_dir();
    assert!(!run.join(".global-report-preparation.json").exists());
    assert!(!run.join("indexes/startup-dependencies/index.json").exists());
    assert!(!run.join(".replay/replay-ca.pem").exists());
    let (_, manifest) = crate::dependency_index::recording::manifest(&run).unwrap();
    let report = temp
        .path()
        .join(".traffic-e2e/local/artifacts/replays/first/report.json");
    let runtime = load(&run, &policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let fingerprint = state.replay_policy.as_ref().unwrap().report().fingerprint;
    assert_eq!(
        Some(&fingerprint),
        config.global_projection_policy.as_ref(),
        "Source facts must not alter compiled policy identity"
    );
    let runtime_identity =
        policy_identity(&config.process_owned_dependencies, Some(&fingerprint)).unwrap();
    let source_bytes = manifest.files.iter().map(|file| file.length).sum();
    let source_sha256 = crate::policy_evidence::digest(
        &serde_json::to_vec(&(
            manifest.files,
            state.dependency_attribution_snapshot.as_ref(),
        ))
        .unwrap(),
    );
    assert!(state.regular_global.contains_key("redis"));
    for protocol in state.regular_global.keys() {
        let evidence = super::regular::prepare_regular(&report, &state, protocol)
            .unwrap()
            .unwrap();
        let reference = evidence_reference(&evidence);
        let (inventory, _) = reference.load::<Inventory>(&report).unwrap();
        let expected = Identity {
            source_sha256: source_sha256.clone(),
            source_bytes,
            policy: runtime_identity.clone(),
            protocol: protocol.clone(),
            layout: state.global_report_layout(protocol).unwrap(),
            semantics: state.global_report_semantics(protocol),
        };
        assert_eq!(inventory.identity, expected);
        super::regular::retain_reference(
            &report,
            expected,
            false,
            Some(&run.join("global-dependencies.jsonl")),
            |_| panic!("prepared report must not visit native rows again"),
        )
        .unwrap();
    }
}

fn evidence_reference(evidence: &regular::RegularEvidence) -> ArtifactReference {
    serde_json::from_value(serde_json::to_value(evidence).unwrap()["inventory"].clone()).unwrap()
}

#[tokio::test]
async fn recording_seals_source_without_reading_a_target_workflow() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, _, _) = recorded(temp.path(), &records()).await;
    let workflow = temp
        .path()
        .join(".traffic-e2e/local/runtime/rewrite/state.json");
    fs::create_dir_all(workflow.parent().unwrap()).unwrap();
    fs::write(&workflow, b"unrelated invalid Target workflow").unwrap();
    recorder.finish_run().await.unwrap();
    let (_, manifest) = crate::dependency_index::recording::manifest(&recorder.run_dir()).unwrap();
    assert!(manifest.capture_complete);
    // The frozen identity retains the run and sealed inventory binding even
    // when there is no overlay. It must not revert to the old hash of `[]`.
    let (decisions, snapshot) = crate::coordination::freeze_dependency_attribution(
        None,
        &recorder.run_dir(),
        &manifest.run_id,
    )
    .unwrap();
    assert!(decisions.is_empty());
    assert_ne!(snapshot, crate::policy_evidence::digest(b"[]"));
    assert!(
        crate::coordination::freeze_dependency_attribution(
            Some(temp.path()),
            &recorder.run_dir(),
            &manifest.run_id,
        )
        .is_err(),
        "fixture must reject attempts to read the unrelated workflow"
    );
}

#[tokio::test]
async fn published_report_rejects_damaged_page() {
    let temp = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(temp.path(), &records()).await;
    recorder.finish_run().await.unwrap();
    let report = temp
        .path()
        .join(".traffic-e2e/local/artifacts/replays/fallback/report.json");
    let runtime = load(&recorder.run_dir(), &policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let evidence = super::regular::prepare_regular(&report, &state, "redis")
        .unwrap()
        .unwrap();
    let (inventory, root) = evidence_reference(&evidence)
        .load::<Inventory>(&report)
        .unwrap();
    assert!(!inventory.pages.is_empty());
    fs::write(root.join("0.json"), b"tampered").unwrap();
    assert!(
        evidence.read(&report, 0, 1, &mut vec![]).is_err(),
        "published evidence cannot silently rebuild damaged pages"
    );
}

#[tokio::test]
async fn unsupported_source_dependency_preserves_recording_status_and_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let mut unsafe_record = records().remove(0);
    unsafe_record["replay_safe"] = false.into();
    let (recorder, _, _) = recorded(temp.path(), &[unsafe_record.clone()]).await;
    assert!(!recorder.finish_run().await.unwrap());
    let report: Value =
        serde_json::from_slice(&fs::read(recorder.run_dir().join("recording-run.json")).unwrap())
            .unwrap();
    assert_eq!(report["status"], "completed");
    let raw = crate::dependency_index::scoped::read_bytes(
        &recorder.run_dir().join("global-dependencies.jsonl"),
    )
    .unwrap();
    let retained: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(retained["replay_safe"], false);
    assert_eq!(retained["capture"]["attribution"]["kind"], "startup");
}

#[tokio::test]
async fn changed_policy_has_distinct_projection_and_moved_recording_replays() {
    let origin = tempfile::tempdir().unwrap();
    let (recorder, config, policy) = recorded(origin.path(), &records()).await;
    recorder.finish_run().await.unwrap();
    let run = recorder.run_dir();
    let initial_policy = fs::read_to_string(&policy).unwrap();
    let initial_report = origin
        .path()
        .join(".traffic-e2e/local/artifacts/replays/initial/report.json");
    let original = load(&run, &policy, &config, &initial_report).await;
    let initial_key = {
        let state = original.state.lock().await;
        let evidence = super::regular::prepare_regular(&initial_report, &state, "redis")
            .unwrap()
            .unwrap();
        evidence_reference(&evidence).key().to_owned()
    };
    drop(original);
    let mut document = crate::policy::parse_policy(&initial_policy).unwrap();
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
    let changed = load(
        &recorder.run_dir(),
        &policy,
        &changed_config,
        &changed_report,
    )
    .await;
    let state = changed.state.lock().await;
    let evidence = super::regular::prepare_regular(&changed_report, &state, "redis")
        .unwrap()
        .unwrap();
    assert_ne!(evidence_reference(&evidence).key(), initial_key);
    drop(state);
    drop(changed);

    let destination = tempfile::tempdir().unwrap();
    let moved = destination
        .path()
        .join(".traffic-e2e/local/recordings/moved");
    copy_tree(&run, &moved);
    let moved_policy = destination.path().join(".traffic-e2e/policy.yaml");
    fs::write(&moved_policy, initial_policy).unwrap();
    fs::remove_dir_all(origin.path().join(".traffic-e2e")).unwrap();
    let report = destination
        .path()
        .join(".traffic-e2e/local/artifacts/replays/moved/report.json");
    let runtime = load(&moved, &moved_policy, &config, &report).await;
    let state = runtime.state.lock().await;
    let evidence = super::regular::prepare_regular(&report, &state, "redis")
        .unwrap()
        .unwrap();
    assert_eq!(evidence_reference(&evidence).key(), initial_key);
    let mut items = vec![];
    evidence.read(&report, 0, 10, &mut items).unwrap();
    assert_eq!(items.len(), 1);
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
