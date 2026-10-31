use super::*;

mod cancelled_delivery;
mod peer_disconnect;
mod streaming;

#[tokio::test(start_paused = true)]
async fn replay_end_finishes_ordinary_case_without_a_post_response_sleep() {
    let temp = tempfile::tempdir().unwrap();
    let collection_dir = temp.path().join("api-user");
    for case_id in ["case-a", "case-b"] {
        let case_dir = collection_dir.join(case_id);
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
    }
    write_test_recording_network_manifest(&collection_dir);
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: collection_dir,
            selected_case_ids: Vec::new(),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".to_string(),
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
    let state = runtime.state.clone();
    let begin = ReplayControlRequest {
        command: "begin".to_string(),
        case_id: Some("case-a".to_string()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    assert_eq!(begin_case(&begin, state.clone()).await["ok"], true);

    let end = ReplayControlRequest {
        command: "end".to_string(),
        case_id: Some("case-a".to_string()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        identity_pairs: Vec::new(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    let started = tokio::time::Instant::now();
    let ended = end_case(&end, state.clone()).await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(ended["ok"], true);
    assert_eq!(state.lock().await.active_case_id, None);
}

#[test]
fn failure_references_report_without_embedding_it() {
    let response = serde_json::json!({
        "ok": false,
        "complete": true,
        "dirty": true,
        "error": "replay evidence is dirty",
        "report": {"large_payload": "x".repeat(1_000_000)},
    });
    let session = serde_json::json!({"report_path": "/tmp/replay-report.json"});

    let message = control_failure_message(&response, &session);

    assert!(message.contains("complete=true; dirty=true"));
    assert!(message.contains("/tmp/replay-report.json"));
    assert!(!message.contains("large_payload"));
    assert!(message.len() < 256);
}

#[cfg(unix)]
#[test]
fn allocated_control_socket_stays_below_unix_path_limit() {
    use std::os::unix::ffi::OsStrExt;

    let socket = crate::replay::allocate_control_socket();

    assert!(socket.starts_with("/tmp"));
    assert!(socket.as_os_str().as_bytes().len() < 100);
}
