//! Actual TCP backpressure must retain Case ownership until delivery or failure.
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
    let runtime = runtime(root, &[], &globals, true).await.unwrap();
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
async fn failed_primary_cleanup_waits_for_partial_native_input_and_retains_case() {
    let temp = tempfile::tempdir().unwrap();
    let (runtime, mut subscriber, task, raw) = partial_input(temp.path()).await;
    // Failed primary cleanup also has to drain inputs already admitted to TCP.
    assert_eq!(
        guards::control(&runtime, json!({"command":"case_failed","case_id":"case"})).await["ok"],
        true
    );
    runtime
        .state
        .lock()
        .await
        .case_dependency_post_response_window = Duration::ZERO;
    let shared = runtime.clone();
    let ending = tokio::spawn(async move {
        guards::control(&shared, json!({"command":"end","case_id":"case"})).await
    });
    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(!ending.is_finished());
    assert_eq!(
        runtime.state.lock().await.active_case_id.as_deref(),
        Some("case")
    );
    assert_eq!(read(&mut subscriber).await, raw);
    let ended = tokio::time::timeout(Duration::from_secs(2), ending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended["ok"], false, "{ended}");
    assert!(
        ended["error"]
            .as_str()
            .unwrap()
            .contains("interaction dependency execution failed")
    );
    let state = runtime.state.lock().await;
    // A failed native primary still requires Target shutdown before release.
    assert_eq!(state.active_case_id.as_deref(), Some("case"));
    assert!(!state.redis.has_case_in_flight());
    assert!(!state.redis.case_has_runtime_failure("case"));
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
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
    assert!(state.redis.case_has_runtime_failure("case"));
    assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 0);
    assert_eq!(state.redis.pubsub.report().unwrap().failed_pushes, 1);
    assert_eq!(
        state.redis.events.unsafe_events[0].case_id.as_deref(),
        Some("case")
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
        guards::control(&runtime, json!({"command":"case_failed","case_id":"case"})).await["ok"],
        true
    );
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        false
    );
    assert_eq!(
        guards::control(
            &runtime,
            json!({"command":"native_event_begin","case_id":"case"})
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
