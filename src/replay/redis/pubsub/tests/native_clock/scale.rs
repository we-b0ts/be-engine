//! Native input rate follows real delivery, retaining order and bounded backpressure.
use super::*;

fn burst(
    root: &Path,
    count: usize,
    lifetime: u64,
    first_padding: usize,
) -> (Vec<Value>, Vec<Vec<u8>>) {
    let (seed, original) = fixture(root);
    let response = root.join("case/expected-response.json");
    let mut completion: Value = serde_json::from_slice(&std::fs::read(&response).unwrap()).unwrap();
    completion["duration_ms"] = lifetime.into();
    completion["interaction"]["end"]["offset_ms"] = lifetime.into();
    std::fs::write(response, completion.to_string()).unwrap();
    let frame = parse_pubsub_push(&original).unwrap().unwrap();
    let value: Value = serde_json::from_slice(&frame.payload).unwrap();
    let mut globals = vec![seed[0].clone()];
    let mut originals = Vec::with_capacity(count);
    for index in 0..count {
        let mut value = value.clone();
        value["data"] = json!([{"index":index}]);
        // All these messages arrive over the same genuine Redis subscription.
        // The Target, rather than the engine, owns its socket room routing.
        value["room"] = if index % 2 == 0 {
            "user:7"
        } else {
            "user:other"
        }
        .into();
        if index == 0 && first_padding > 0 {
            value["data"][0]["padding"] = "x".repeat(first_padding).into();
        }
        let raw = crate::redis::encode_array(&[
            b"message",
            b"jobs",
            &serde_json::to_vec(&value).unwrap(),
        ]);
        let mut incoming = seed[1].clone();
        incoming["response"] = capture(&raw);
        globals.push(incoming);
        originals.push(raw);
    }
    (globals, originals)
}

#[tokio::test]
async fn a_native_plan_keeps_more_than_65536_original_slots_without_materializing_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let (mut globals, _) = fixture(temp.path());
    let notification = globals.pop().unwrap();
    let count = 65_537;
    globals.extend(std::iter::repeat_n(notification, count));
    let runtime = recording::ambient_runtime(temp.path(), &[], &globals, true)
        .await
        .expect("a complete finite Source inventory must not hit a fixed projection-count cap");
    let state = runtime.state.lock().await;
    let pubsub = &state.redis.pubsub;
    assert!(
        pubsub.pushes.is_empty(),
        "original notifications stay paged"
    );
    assert_eq!(pubsub.indexed.total, count);
    assert_eq!(pubsub.native_clock.timing_evidence(CASE).len(), count);
    assert!(pubsub.native_clock.needs_observer(CASE));
    let report = pubsub.report().unwrap();
    assert_eq!(report.recorded_pushes, count);
    assert_eq!(report.delivered_pushes, 0);
    assert_eq!(report.failed_pushes, 0);
}

#[tokio::test]
async fn a_native_burst_exceeds_two_hundred_messages_per_second_without_dropping_other_rooms() {
    let temp = tempfile::tempdir().unwrap();
    // The old one-input-per-5ms poll could deliver at most 400 before this
    // immutable two-second lifecycle expired, leaving the remainder unused.
    let (globals, originals) = burst(temp.path(), 600, 2000, 0);
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
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
    tokio::time::timeout(Duration::from_secs(4), async {
        for original in &originals {
            assert_eq!(&read(&mut subscriber).await, original);
        }
    })
    .await
    .expect("finite original burst was throttled past its Source lifecycle");
    guards::silent(&mut subscriber).await;
    let state = runtime.state.lock().await;
    let report = state.redis.pubsub.report().unwrap();
    assert_eq!(report.recorded_pushes, 600);
    assert_eq!(report.delivered_pushes, 600);
    assert_eq!(report.failed_pushes, 0);
    assert!(!state.redis.has_case_in_flight());
    task.abort();
}

#[tokio::test]
async fn a_full_native_delivery_queue_applies_backpressure_without_failing_source_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let (globals, originals) = burst(temp.path(), 300, 10000, 8 * 1024 * 1024);
    let runtime = runtime(temp.path(), &[], &globals, true).await.unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        SUBSCRIBED
    );
    let mut subscriber = RedisBufferedReader::new(subscriber.inner, 16 * 1024 * 1024);
    let epoch = guards::begin(&runtime).await;
    assert_eq!(
        guards::connected(&runtime, epoch, "/chat").await["ok"],
        true
    );
    // One real write is blocked by TCP and all 256 bounded channel slots are
    // reserved. The remaining Source inputs must stay pending rather than fail.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .state
                .lock()
                .await
                .redis
                .pubsub
                .case_delivery_diagnostic()["count"]
                == 257
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fixture did not fill the real bounded delivery queue");
    tokio::time::sleep(Duration::from_millis(35)).await;
    {
        let state = runtime.state.lock().await;
        let report = state.redis.pubsub.report().unwrap();
        assert_eq!(report.delivered_pushes, 0);
        assert_eq!(report.failed_pushes, 0);
        assert!(state.redis.events.unsafe_events.is_empty());
        assert_eq!(state.redis.pubsub.case_delivery_diagnostic()["count"], 257);
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        for original in &originals {
            assert_eq!(&read(&mut subscriber).await, original);
        }
    })
    .await
    .unwrap();
    guards::silent(&mut subscriber).await;
    let state = runtime.state.lock().await;
    let report = state.redis.pubsub.report().unwrap();
    assert_eq!(report.delivered_pushes, 300);
    assert_eq!(report.failed_pushes, 0);
    assert!(!state.redis.has_case_in_flight());
    task.abort();
}
