use super::*;
use crate::replay::ReplayState;
use std::sync::Arc;
use tokio::sync::Mutex;

const SOURCE: &str = r#"{"ids":["B","A","A"],"ordered":[1,2]}"#;
const TARGET: &str = r#"{"ordered":[1,2],"ids":["A","B","A"]}"#;

pub(super) async fn spawn(
    case: &Path,
    policy: Option<PathBuf>,
) -> (
    SocketAddr,
    Arc<Mutex<ReplayState>>,
    tokio::task::JoinHandle<()>,
) {
    super::super::write_test_recording_network_manifest(case);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: case.into(),
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: addr,
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(case.join(".replay/ca.pem")),
            ca_key_path: Some(case.join(".replay/ca-key.pem")),
            policy_path: policy,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        addr,
    )
    .await
    .unwrap();
    let state = runtime.state.clone();
    let task = tokio::spawn(async move {
        runtime.run_tcp(listener).await.unwrap();
    });
    (addr, state, task)
}
pub(super) async fn request(client: &mut TcpStream, parts: &[&str], expected: &[u8]) {
    let mut bytes = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        bytes.extend_from_slice(format!("${}\r\n{}\r\n", part.len(), part).as_bytes());
    }
    client.write_all(&bytes).await.unwrap();
    let mut response = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, expected);
}
#[tokio::test]
async fn redis_value_discovery_plan_apply_then_real_set_get_preserves_lane_and_policy_usage() {
    let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
    let case = temp.path().join("apis/models/case");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let connection = Uuid::new_v4();
    let set = redis_hash_dependency(
        connection,
        1,
        "SET",
        &["members:1", SOURCE, "EX", "900"],
        b"+OK\r\n",
    );
    let get = redis_dependency(connection, 2, "members:1", b"$8\r\nrecorded\r\n");
    std::fs::write(case.join("dependencies.jsonl"), format!("{set}\n{get}\n")).unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"GET","uri":"/models"}"#,
    )
    .unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let (addr, state, task) = spawn(&case, None).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &["SET", "members:1", TARGET, "EX", "900"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    let report = temp.path().join("replay.json");
    {
        let mut state = state.lock().await;
        state.finalized_at = Some(Utc::now());
        std::fs::write(
            &report,
            serde_json::to_vec(&state.snapshot_report()).unwrap(),
        )
        .unwrap();
    }
    task.abort();
    let policy = temp.path().join("policy.yaml");
    crate::replay::write_policy_fixture(
        &policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    std::fs::write(
        &policy,
        "format: traffic-policy/v2\njson: {fields: {/ids: {kind: unordered}}}\n",
    )
    .unwrap();
    let (addr, state, task) = spawn(&case, Some(policy)).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    request(
        &mut client,
        &["GET", "members:1"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    request(
        &mut client,
        &["SET", "members:1", TARGET, "EX", "901"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    request(
        &mut client,
        &["SET", "members:1", TARGET, "EX", "900"],
        b"+OK\r\n",
    )
    .await;
    request(&mut client, &["GET", "members:1"], b"$8\r\nrecorded\r\n").await;
    request(
        &mut client,
        &["SET", "members:1", TARGET, "EX", "900"],
        b"-ERR no recorded Redis dependency matched\r\n",
    )
    .await;
    let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
    assert_eq!(report["redis"]["matched_count"], 2);
    assert_eq!(
        report["redis"]["unmatched"][0]["diagnostic"]["kind"],
        "lane_blocked"
    );
    let usage = report["replay_policy"]["global_formats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|format| format["id"] == "global.json")
        .unwrap();
    assert_eq!(usage["validations"], 1);
    task.abort();
}
