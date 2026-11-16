use super::*;

mod cancelled_delivery;
mod finalization;
mod peer_disconnect;

#[tokio::test(start_paused = true)]
async fn replay_end_waits_for_close_tails_and_caps_rolling_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let collection_dir = temp.path().join("api-user");
    for case_id in ["case-a", "case-b", "case-c"] {
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
        parameters: Default::default(),
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
        parameters: Default::default(),
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

    let request = |command: &str, case: &str| ReplayControlRequest {
        command: command.into(),
        case_id: Some(case.into()),
        fail_on_dirty: true,
        fail_on_incomplete: false,
        parameters: Default::default(),
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    };
    for (case, command, activity_at, remaining) in [
        (
            "case-b",
            "case_close_tail",
            Duration::from_secs(14),
            Duration::from_secs(15),
        ),
        (
            "case-c",
            "case_client_aborted",
            Duration::from_secs(299),
            Duration::from_secs(1),
        ),
    ] {
        assert_eq!(
            begin_case(&request("begin", case), state.clone()).await["ok"],
            true
        );
        let (observed, _) =
            handle_control_request(request(command, case), state.clone(), None, None).await;
        assert_eq!(observed["ok"], true);
        tokio::time::advance(activity_at).await;
        let latest = tokio::time::Instant::now();
        {
            let mut active = state.lock().await;
            // Independent post-abort dependency observations renew idle, but
            // a failed case still retains its original absolute bound.
            active.target_observations.watch_abort_tail(case, latest);
            case_cleanup::mark_failed(&mut active, case).unwrap();
        }
        let ended = end_case(&request("end", case), state.clone()).await;
        assert_eq!(ended["ok"], true);
        assert_eq!(latest.elapsed(), remaining);
        assert_eq!(state.lock().await.active_case_id, None);
    }
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
