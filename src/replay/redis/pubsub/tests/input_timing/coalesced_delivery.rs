//! Native batching keeps exact Source coverage separate from input deadlines.
use super::*;

fn write_program(root: &Path, next_ms: u64, document: Value) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::create_dir_all(root.join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(root).unwrap();
    std::fs::write(root.join("case/request.json"), input(next_ms).to_string()).unwrap();
    std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
    std::fs::write(root.join(".traffic-e2e/policy.yaml"), document.to_string()).unwrap();
}

fn append_policy() -> Value {
    let mut rule = crate::replay::redis::append::tests::rule();
    rule["match"]["api"] = json!("GET /socket.io/");
    json!({"format":"traffic-policy/v3","rules":[rule]})
}

fn append_events(split_source: bool, duration_ms: u64) -> Vec<Value> {
    let event = crate::replay::redis::append::tests::event;
    let mut records = if split_source {
        vec![
            event(1, "APPEND", &[b"content:1", b"ab"], b":2\r\n"),
            event(2, "APPEND", &[b"content:1", b"cd"], b":4\r\n"),
        ]
    } else {
        vec![event(1, "APPEND", &[b"content:1", b"abcd"], b":4\r\n")]
    };
    for (position, record) in records.iter_mut().enumerate() {
        let completed = START.parse::<chrono::DateTime<chrono::Utc>>().unwrap()
            + chrono::TimeDelta::milliseconds(100 + position as i64 * 50);
        record["timestamp"] = json!(completed);
        record["request_started_at"] =
            json!(completed - chrono::TimeDelta::milliseconds(duration_ms as i64));
        record["duration_ms"] = json!(duration_ms);
    }
    let mut get = event(
        records.len() as u64 + 1,
        "GET",
        &[b"content:1"],
        b"$4\r\nabcd\r\n",
    );
    get["timestamp"] = json!("2020-01-01T00:00:31Z");
    get["request_started_at"] = get["timestamp"].clone();
    records.push(get);
    records
}

#[tokio::test]
async fn merged_append_delivers_every_covered_source_reference_after_wire() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 30_000, append_policy());
    let runtime = runtime(temp.path(), &append_events(true, 50), &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    redis
        .inner
        .write_all(&crate::redis::encode_array(&[
            b"APPEND",
            b"content:1",
            b"abcd",
        ]))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let responding = runtime
                .state
                .lock()
                .await
                .redis
                .exchanges
                .iter()
                .take(2)
                .all(|exchange| exchange.status == ReplayExchangeStatus::Responding);
            if responding {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut wait = tokio::spawn(async move { observer.wait(3, vec![2]).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut wait)
            .await
            .is_err()
    );
    assert_eq!(read(&mut redis).await, b":4\r\n");
    let advance = tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    let state = runtime.state.lock().await;
    assert!(
        state
            .redis
            .exchanges
            .iter()
            .take(2)
            .all(|exchange| exchange.status.is_consumed())
    );
    assert!(
        state.redis.exchanges[2].status.is_available(),
        "future read must not gate the earlier input"
    );
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn partial_append_does_not_authorize_compression_until_source_piece_is_covered() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 30_000, append_policy());
    let runtime = runtime(temp.path(), &append_events(false, 0), &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert_eq!(
        send(&mut redis, &[b"APPEND", b"content:1", b"ab"]).await,
        b":2\r\n"
    );
    let mut wait = tokio::spawn(async move { observer.wait(3, vec![2]).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut wait)
            .await
            .is_err()
    );
    assert_eq!(
        runtime.state.lock().await.redis.exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    assert_eq!(
        send(&mut redis, &[b"APPEND", b"content:1", b"cd"]).await,
        b":4\r\n"
    );
    let advance = tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn partial_append_keeps_original_input_deadline_available_for_its_continuation() {
    let temp = tempfile::tempdir().unwrap();
    write_program(temp.path(), 2_500, append_policy());
    let runtime = runtime(temp.path(), &append_events(false, 0), &[], false)
        .await
        .unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert_eq!(
        send(&mut redis, &[b"APPEND", b"content:1", b"ab"]).await,
        b":2\r\n"
    );
    let advance = tokio::time::timeout(Duration::from_secs(4), observer.wait(3, vec![2]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        advance.removed_ms, 0,
        "partial Source coverage cannot authorize compression"
    );
    assert_eq!(
        runtime.state.lock().await.redis.exchanges[0].status,
        ReplayExchangeStatus::Responding
    );
    assert_eq!(
        send(&mut redis, &[b"APPEND", b"content:1", b"cd"]).await,
        b":4\r\n"
    );
    redis_task.abort();
    control.abort();
}

#[tokio::test]
async fn coalesced_absent_reads_deliver_the_entire_native_observation_epoch() {
    let temp = tempfile::tempdir().unwrap();
    let document = json!({"format":"traffic-policy/v3","rules":[{
        "id":"absent","match":{"api":"GET /socket.io/","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},
            "operation":"GET","key":{"kind":"affix","prefix":"cancel:"}},
        "effect":{"kind":"redis_read_observation"},
        "proof":{"source":"cancel.py:10","fact":"Source polls absent state between finite deletion boundaries; repeated reads may coalesce"}
    }]});
    write_program(temp.path(), 30_000, document);
    let event = crate::replay::redis::append::tests::event;
    let mut records = vec![
        event(1, "DEL", &[b"cancel:1"], b":1\r\n"),
        event(2, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(3, "GET", &[b"cancel:1"], b"$-1\r\n"),
        event(4, "DEL", &[b"cancel:1"], b":0\r\n"),
    ];
    for (position, record) in records.iter_mut().take(3).enumerate() {
        record["timestamp"] = json!(
            START.parse::<chrono::DateTime<chrono::Utc>>().unwrap()
                + chrono::TimeDelta::milliseconds(50 + position as i64 * 50)
        );
        record["request_started_at"] = record["timestamp"].clone();
    }
    records[3]["timestamp"] = json!("2020-01-01T00:00:31Z");
    records[3]["request_started_at"] = records[3]["timestamp"].clone();
    let runtime = runtime(temp.path(), &records, &[], false).await.unwrap();
    let (mut redis, redis_task) = connect(&runtime).await;
    let (session, control) = serve_control(temp.path(), &runtime).await;
    let observer = crate::replay::input_timing_observer(&session, "case", SocketIoTiming::Auto)
        .await
        .unwrap();
    assert_eq!(send(&mut redis, &[b"DEL", b"cancel:1"]).await, b":1\r\n");
    assert_eq!(send(&mut redis, &[b"GET", b"cancel:1"]).await, b"$-1\r\n");
    let advance = tokio::time::timeout(Duration::from_secs(1), observer.wait(3, vec![2]))
        .await
        .unwrap()
        .unwrap();
    assert!(advance.removed_ms > 29_000);
    let state = runtime.state.lock().await;
    assert!(
        state
            .redis
            .exchanges
            .iter()
            .take(3)
            .all(|exchange| exchange.status.is_consumed())
    );
    assert!(state.redis.exchanges[3].status.is_available());
    redis_task.abort();
    control.abort();
}
