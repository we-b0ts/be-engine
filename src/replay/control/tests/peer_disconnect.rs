//! Cancelled observers cannot terminate Replay or discard committed finalization.
use super::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn abandoned_control_peers_preserve_the_server_case_and_final_report() {
    let temp = tempfile::tempdir().unwrap();
    let collection = temp.path().join("cases");
    let case = collection.join("case-a");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(case.join("dependencies.jsonl"), "").unwrap();
    write_test_recording_network_manifest(&collection);
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: collection,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: None,
            http_ignore_query_params: Vec::new(),
            process_owned_dependencies: Vec::new(),
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    let socket = crate::replay::allocate_control_socket();
    let session = temp.path().join("session.json");
    let report = temp.path().join("report.json");
    let state = runtime.state.clone();
    let server = tokio::spawn(run_control_socket(
        state.clone(),
        Some(report.clone()),
        Some(session.clone()),
        Some(socket.clone()),
    ));
    let config = |command: &str| MysqlReplayControlConfig {
        session_path: session.clone(),
        command: command.into(),
        case_id: Some("case-a".into()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        wait_timeout: Some(Duration::from_secs(2)),
    };
    send_control_request(config("wait_ready")).await.unwrap();

    // A polling task can disappear before it sends any bytes.
    drop(UnixStream::connect(&socket).await.unwrap());
    assert_eq!(
        send_control_request(config("begin")).await.unwrap()["ok"],
        true
    );

    // Force cancellation while the observation is waiting for the state lock.
    let guard = state.lock().await;
    let mut observer = UnixStream::connect(&socket).await.unwrap();
    observer
        .write_all(b"{\"command\":\"case_execution_status\",\"case_id\":\"case-a\"}\n")
        .await
        .unwrap();
    drop(observer);
    drop(guard);
    let status = tokio::time::timeout(
        Duration::from_secs(2),
        send_control_request(config("status")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(status["session"]["active_case_id"], "case-a");
    assert!(!server.is_finished());
    assert_eq!(
        send_control_request(config("end")).await.unwrap()["ok"],
        true
    );

    // The successful finalize operation still stops after publishing if its
    // acknowledgement has no reader. Peer loss cannot undo that operation.
    let guard = state.lock().await;
    let mut finalizer = UnixStream::connect(&socket).await.unwrap();
    finalizer
        .write_all(b"{\"command\":\"finalize\"}\n")
        .await
        .unwrap();
    drop(finalizer);
    drop(guard);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let report: Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(report["finalized"], true);
    assert_eq!(report["complete"], true);
    assert!(state.lock().await.active_case_id.is_none());
}
