//! Shared reads do not reinterpret sibling Case notifications as exchanges.
use super::*;

fn fixture() -> (
    crate::replay::policy::test_fixture::ManagedFixtureDirectory,
    Value,
    Vec<u8>,
) {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed","run_id":"one"}"#,
    )
    .unwrap();
    let origin = temp.path().join("apis/example/origin");
    fs::create_dir_all(&origin).unwrap();
    let capture = |data: &str| json!({"encoding":"utf8","data":data,"truncated":false});
    let record = json!({"event_type":"redis_exchange","connection_id":Uuid::new_v4(),"sequence":1,
        "target_host":"redis.test","target_port":6379,"database":0,"username":null,"resp_version":2,
        "command":"GET","args":[capture("shared")],"response":capture("$5\r\ntoken\r\n"),
        "response_kind":"bulk_string","duration_ms":0,"replay_safe":true});
    let push = json!({"event_type":"redis_pub_sub_push","connection_id":Uuid::new_v4(),"subscription_sequence":1,
        "target_host":"redis.test","target_port":6379,"database":0,"username":null,
        "response":capture("*3\r\n$7\r\nmessage\r\n$4\r\njobs\r\n$4\r\nlive\r\n"),
        "duration_ms":0,"replay_safe":true});
    let bytes = format!("{record}\n{push}\n").into_bytes();
    fs::write(origin.join("dependencies.jsonl"), &bytes).unwrap();
    fs::write(
        origin.join("request.json"),
        r#"{"method":"GET","uri":"/example"}"#,
    )
    .unwrap();
    fs::write(origin.join("expected-response.json"), "{}").unwrap();
    (temp, record, bytes)
}

fn policy(root: &Path) -> std::path::PathBuf {
    let path = root.join("policy.yaml");
    crate::replay::write_policy_fixture(&path, "version: 3\nexpected_response: assertions_only\ndependency_rules:\n- id: shared-token\n  protocol: redis\n  target: {}\n  redis: {command: GET, key: shared}\n  replay_scope: recording_run\n  source_evidence: 'auth.py:ensure_token reads a finite shared token across requests'\n").unwrap();
    path
}

#[test]
fn loading_an_unselected_sibling_skips_pubsub_frames_and_preserves_shared_read_inventory() {
    let (temp, _, bytes) = fixture();
    let policy = policy(temp.path());
    let mut state = RedisReplayState::default();
    load(
        &mut state,
        temp.path(),
        Some(&policy),
        &BTreeMap::new(),
        &mut BTreeMap::new(),
        &[],
    )
    .unwrap();
    assert_eq!(state.exchanges.len(), 1);
    assert_eq!(state.exchanges[0].record.command, "GET");
    assert_eq!(state.exchanges[0].source, ReplaySource::Startup);
    assert_eq!(state.exchanges[0].case_id.as_deref(), Some("origin"));
    assert_eq!(
        state.exchanges[0].shared_rule_id.as_deref(),
        Some("shared-token")
    );
    assert!(state.exchanges[0].status.is_available());
    assert!(state.pubsub.report().is_none());
    assert_eq!(
        fs::read(temp.path().join("apis/example/origin/dependencies.jsonl")).unwrap(),
        bytes
    );
}

#[test]
fn sharing_proof_skips_pubsub_frames_without_losing_exact_read_evidence() {
    let (temp, record, bytes) = fixture();
    let record: RecordedExchange = serde_json::from_value(record).unwrap();
    let fingerprint = recorded_fingerprint(&record, &[b"shared".to_vec()]);
    let report = temp.path().join("report.json");
    fs::write(
        &report,
        json!({"finalized":true,"redis":{"unmatched":[{
            "case_id":"consumer","request_fingerprint":fingerprint,"command":"GET",
            "target":{"host":"redis.test","port":6379}
        }]}})
        .to_string(),
    )
    .unwrap();
    let selector =
        serde_json::from_value(json!({"read":{"command":"GET","key":"shared"}})).unwrap();
    let proof = verify_candidate(temp.path(), &report, &selector).unwrap();
    assert_eq!(proof["matching_exchanges"], 1);
    assert_eq!(proof["candidate"]["origin_case_id"], "origin");
    assert_eq!(proof["candidate"]["source_line"], 1);
    assert_eq!(
        fs::read(temp.path().join("apis/example/origin/dependencies.jsonl")).unwrap(),
        bytes
    );
}

#[test]
fn notifications_do_not_weaken_the_complete_shared_connection_lane_guard() {
    let (temp, mut record, _) = fixture();
    let path = temp.path().join("apis/example/origin/dependencies.jsonl");
    let mut bytes = fs::read(&path).unwrap();
    record["command"] = json!("SET");
    record["sequence"] = json!(2);
    record["args"] = json!([{"encoding":"utf8","data":"shared","truncated":false},{"encoding":"utf8","data":"new-token","truncated":false}]);
    bytes.extend_from_slice(format!("{record}\n").as_bytes());
    fs::write(path, bytes).unwrap();
    let policy = policy(temp.path());
    let result = load(
        &mut RedisReplayState::default(),
        temp.path(),
        Some(&policy),
        &BTreeMap::new(),
        &mut BTreeMap::new(),
        &[],
    );
    assert!(
        format!("{:#}", result.unwrap_err()).contains("cannot split a recorded connection lane")
    );
}

#[tokio::test]
#[ignore = "requires TRAFFIC_E2E_SHARED_RECORDING and TRAFFIC_E2E_SHARED_CASE"]
async fn recorded_focused_case_prepares_without_starting_a_target() {
    use crate::replay::{
        ReplayConfig, ReplayDependencyLoading, ReplayLifecycleConfig, ReplayRuntime,
    };
    let root = std::path::PathBuf::from(
        std::env::var_os("TRAFFIC_E2E_SHARED_RECORDING").expect("recording root"),
    );
    let cases: Vec<String> = std::env::var("TRAFFIC_E2E_SHARED_CASE")
        .expect("selected Cases")
        .split(',')
        .map(str::to_owned)
        .collect();
    let project_root = root
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == ".traffic-e2e"))
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let project = crate::AppConfig::load(project_root.join(".traffic-e2e/project.yaml")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let addr = "127.0.0.1:0".parse().unwrap();
    let runtime = ReplayRuntime::load_with_lifecycle(
        ReplayConfig {
            case_dir: root,
            selected_case_ids: cases.clone(),
            dns_listen: addr,
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: Some(project_root.join(".traffic-e2e/policy.yaml")),
            http_ignore_query_params: vec![],
            process_owned_dependencies: project.process_owned_dependencies,
            allowed_unused_http: None,
        },
        addr,
        addr,
        ReplayLifecycleConfig {
            dependency_loading: ReplayDependencyLoading {
                lazy_cases: true,
                cache_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for case in cases {
        crate::replay::deferred::prepare_case(runtime.state.clone(), &case)
            .await
            .unwrap();
    }
}

#[test]
fn malformed_exchanges_are_not_treated_as_unrelated_notifications() {
    let (_, mut record, _) = fixture();
    record.as_object_mut().unwrap().remove("sequence");
    let error = decode_exchange(&serde_json::to_vec(&record).unwrap()).unwrap_err();
    assert!(format!("{error:#}").contains("missing field `sequence`"));
    assert!(decode_exchange(br#"{"event_type":"http_exchange"}"#).is_err());
}
