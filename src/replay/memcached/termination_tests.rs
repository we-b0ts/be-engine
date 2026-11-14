use super::super::{MysqlReplayConfig, ReplayRuntime};
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start(
    prefix: &[u8],
) -> (
    tempfile::TempDir,
    Arc<ReplayRuntime>,
    TcpStream,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let frames = if prefix.is_empty() {
        Vec::new()
    } else {
        vec![serde_json::json!({"encoding":"base64", "data":STANDARD.encode(prefix)})]
    };
    let offsets = if prefix.is_empty() {
        Vec::new()
    } else {
        vec![30]
    };
    let event = serde_json::json!({
        "event_type":"memcached_exchange", "connection_id":Uuid::nil(), "sequence":1,
        "target_host":"cache.internal", "target_port":11211, "wire_protocol":"binary",
        "command":"stat", "opcode":16, "key":null, "args":[], "value":null, "extras":null,
        "cas":null, "quiet":false, "noreply":false, "no_response":false,
        "response_frames":frames, "response_frame_offsets_ms":offsets, "replay_safe":true,
        "outcome":{"terminated":{"side":"server", "kind":"eof", "scope":"write_half"}}, "duration_ms":100
    });
    tokio::fs::write(
        case.join("dependencies.jsonl"),
        serde_json::to_vec(&event).unwrap(),
    )
    .await
    .unwrap();
    crate::replay::write_test_recording_network_manifest(&case);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let runtime = Arc::new(
        ReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case.clone(),
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: addr,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(case.join(".replay/ca.pem")),
                ca_key_path: Some(case.join(".replay/ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            addr,
        )
        .await
        .unwrap(),
    );
    let task_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        task_runtime.run_tcp(listener).await.unwrap();
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut request = [0; 24];
    request[0] = 0x80;
    request[1] = 0x10;
    request[12..16].copy_from_slice(&42_u32.to_be_bytes());
    client.write_all(&request).await.unwrap();
    (temp, runtime, client, task)
}

#[tokio::test]
async fn delivers_timed_binary_prefix_with_live_opaque_then_eof() {
    let mut prefix = vec![0; 24];
    prefix[0] = 0x81;
    prefix[1] = 0x10;
    prefix[2..4].copy_from_slice(&3_u16.to_be_bytes());
    prefix[8..12].copy_from_slice(&4_u32.to_be_bytes());
    prefix[12..16].copy_from_slice(&7_u32.to_be_bytes());
    prefix.extend_from_slice(b"key1");
    let (_temp, runtime, mut client, task) = start(&prefix).await;
    let started = tokio::time::Instant::now();
    let mut delivered = vec![0; prefix.len()];
    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        client.read_exact(&mut delivered),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&delivered[12..16], &42_u32.to_be_bytes());
    prefix[12..16].copy_from_slice(&42_u32.to_be_bytes());
    assert_eq!(delivered, prefix);
    assert!(started.elapsed() >= std::time::Duration::from_millis(20));
    let mut probe = [0];
    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.read(&mut probe)
        )
        .await
        .unwrap()
        .unwrap(),
        0
    );
    for _ in 0..20 {
        if runtime
            .state
            .lock()
            .await
            .protocols
            .memcached
            .events
            .matched_count
            == 1
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .protocols
            .memcached
            .events
            .matched_count,
        1
    );
    drop(client);
    task.abort();
}

#[tokio::test]
async fn target_fin_before_server_termination_stays_dirty_and_unconsumed() {
    let (_temp, runtime, mut client, task) = start(&[]).await;
    client.shutdown().await.unwrap();
    for _ in 0..40 {
        if !runtime
            .state
            .lock()
            .await
            .protocols
            .memcached
            .events
            .unsafe_events
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let state = runtime.state.lock().await;
    assert_eq!(state.protocols.memcached.events.matched_count, 0);
    assert!(!state.protocols.memcached.events.unsafe_events.is_empty());
    assert_eq!(
        state.protocols.memcached.exchanges[0].status,
        ReplayExchangeStatus::Failed
    );
    task.abort();
}
