//! Actual TCP backpressure retains Case ownership until admitted delivery drains.
use super::*;

async fn partial_input(
    root: &Path,
) -> (
    Arc<ReplayRuntime>,
    RedisBufferedReader<TcpStream>,
    tokio::task::JoinHandle<Result<()>>,
    Vec<u8>,
) {
    let (mut globals, original) = fixture(root);
    let frame = parse_pubsub_push(&original).unwrap().unwrap();
    let mut payload: Value = serde_json::from_slice(&frame.payload).unwrap();
    // Larger than the actual loopback TCP send window, within the input bound.
    payload["data"][0]["padding"] = "x".repeat(8 * 1024 * 1024).into();
    let raw =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&payload).unwrap()]);
    globals[1]["response"] = capture(&raw);
    std::fs::write(
        root.join("case/expected-response.json"),
        json!({"duration_ms":10000,
        "interaction":{"version":1,"protocol":"socket_io","events":[],
        "end":{"clean":true,"reason":"business_idle","offset_ms":10000}}})
        .to_string(),
    )
    .unwrap();
    let mut runtime = runtime(root, &[], &globals, true).await.unwrap();
    if root.join("unselected").is_dir() {
        // This test needs both real published Cases in its replay scope.
        let case_dir = runtime.state.lock().await.cases[CASE]
            .dir
            .parent()
            .unwrap()
            .to_path_buf();
        let addr = "127.0.0.1:0".parse().unwrap();
        runtime = Arc::new(
            ReplayRuntime::load_with_lifecycle(
                ReplayConfig {
                    case_dir,
                    selected_case_ids: vec![],
                    dns_listen: addr,
                    tcp_listen: addr,
                    fake_cidr: "198.18.0.0/15".into(),
                    report_path: None,
                    session_path: None,
                    control_socket_path: None,
                    ca_cert_path: Some(root.join("ca.pem")),
                    ca_key_path: Some(root.join("ca-key.pem")),
                    policy_path: None,
                    http_ignore_query_params: vec![],
                    process_owned_dependencies: vec![],
                    allowed_unused_http: None,
                },
                addr,
                addr,
                ReplayLifecycleConfig {
                    dependency_loading: ReplayDependencyLoading {
                        lazy_cases: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        let begun = guards::control(&runtime, json!({"command":"begin","case_id":CASE})).await;
        assert_eq!(begun["ok"], true, "{begun}");
    }
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    let epoch = guards::begin(&runtime).await;
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        true
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime.state.lock().await.redis.has_case_in_flight() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(35)).await;
    let state = runtime.state.lock().await;
    assert!(
        state.redis.has_case_in_flight(),
        "fixture must exercise real backpressure"
    );
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
    drop(state);
    let subscriber = RedisBufferedReader::new(subscriber.inner, 16 * 1024 * 1024);
    (runtime, subscriber, task, raw)
}

#[tokio::test]
async fn failed_primary_cleanup_waits_for_partial_native_input_before_next_case() {
    let temp = tempfile::tempdir().unwrap();
    let next_case = "00000000-0000-0000-0000-000000000124";
    std::fs::create_dir(temp.path().join("unselected")).unwrap();
    std::fs::write(
        temp.path().join("unselected/request.json"),
        json!({"method":"GET","uri":"/next","timestamp":"2020-01-01T00:11:00Z"}).to_string(),
    )
    .unwrap();
    let (runtime, mut subscriber, task, raw) = partial_input(temp.path()).await;
    // Failed primary cleanup also has to drain inputs already admitted to TCP.
    assert_eq!(
        guards::control(&runtime, json!({"command":"case_failed","case_id":CASE})).await["ok"],
        true
    );
    runtime
        .state
        .lock()
        .await
        .case_dependency_post_response_window = Duration::ZERO;
    let shared = runtime.clone();
    let ending = tokio::spawn(async move {
        guards::control(&shared, json!({"command":"end","case_id":CASE})).await
    });
    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(!ending.is_finished());
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some(CASE)
    );
    assert_eq!(
        guards::control(&runtime, json!({"command":"begin","case_id":next_case})).await["ok"],
        false
    );
    assert!(runtime.state.lock().await.redis.has_case_in_flight());
    assert_eq!(
        runtime
            .state
            .lock()
            .await
            .redis
            .pubsub
            .report()
            .unwrap()
            .delivered_pushes,
        0
    );
    assert_eq!(read(&mut subscriber).await, raw);
    let ended = tokio::time::timeout(Duration::from_secs(2), ending)
        .await
        .unwrap()
        .unwrap();
    // The primary failure is owned by the caller; all admitted dependency I/O
    // completed successfully and must not create a dependency failure.
    assert_eq!(ended["ok"], true, "{ended}");
    assert_eq!(ended["dirty"], false);
    let state = runtime.state.lock().await;
    assert!(state.active_case_id.is_none());
    assert!(!state.redis.has_case_in_flight());
    assert!(!state.redis.case_has_runtime_failure(CASE));
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
    assert!(state.redis.snapshot().unused_case.is_empty());
    drop(state);
    assert_eq!(
        guards::control(&runtime, json!({"command":"begin","case_id":next_case})).await["ok"],
        true
    );
    assert_eq!(
        guards::control(&runtime, json!({"command":"end","case_id":next_case})).await["ok"],
        true
    );
    task.abort();
}

#[tokio::test]
async fn a_closed_subscriber_leaves_partial_native_input_failed_and_case_dirty() {
    let temp = tempfile::tempdir().unwrap();
    let (runtime, subscriber, task, _) = partial_input(temp.path()).await;
    drop(subscriber);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let state = runtime.state.lock().await;
    assert!(!state.redis.has_case_in_flight());
    assert!(state.redis.case_has_runtime_failure(CASE));
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 1);
    assert_eq!(
        state.redis.events.unsafe_events[0].case_id.as_deref(),
        Some(CASE)
    );
}

#[tokio::test]
async fn closing_a_case_prevents_future_native_input_admission() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, _) = fixture(temp.path());
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    let epoch = guards::begin(&runtime).await;
    assert_eq!(
        guards::control(&runtime, json!({"command":"case_failed","case_id":CASE})).await["ok"],
        true
    );
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        false
    );
    assert_eq!(
        guards::control(
            &runtime,
            json!({"command":"native_event_begin","case_id":CASE})
        )
        .await["enabled"],
        false
    );
    tokio::time::sleep(Duration::from_millis(55)).await;
    guards::silent(&mut subscriber).await;
    let state = runtime.state.lock().await;
    assert!(!state.redis.has_case_in_flight());
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 0);
    task.abort();
}
