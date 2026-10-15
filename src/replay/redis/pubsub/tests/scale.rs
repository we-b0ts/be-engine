use super::*;

#[tokio::test]
async fn more_than_65536_notifications_use_pages_with_exact_counts_and_fresh_consumption() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let raw = crate::redis::encode_array(&[b"message", b"jobs", b"opaque-background-message"]);
    std::fs::create_dir(dir.path().join("case")).unwrap();
    std::fs::write(dir.path().join("case/dependencies.jsonl"), "").unwrap();
    let mut output = std::io::BufWriter::new(
        std::fs::File::create(dir.path().join("global-dependencies.jsonl")).unwrap(),
    );
    writeln!(
        output,
        "{}",
        exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation)
    )
    .unwrap();
    let notification = push(sub, None, &raw, 60000).to_string();
    for _ in 0..65537 {
        writeln!(output, "{notification}").unwrap();
    }
    output.flush().unwrap();
    drop(output);
    for lazy in [true, false] {
        let runtime = load_runtime(dir.path(), lazy).await.unwrap();
        let state = runtime.state.lock().await;
        assert!(state.redis.pubsub.pushes.is_empty());
        assert_eq!(state.redis.pubsub.indexed.total, 65537);
        assert_eq!(state.redis.pubsub.indexed.delivered, 0);
        let report = state.redis.snapshot();
        assert_eq!(report.unused_global_count, Some(65538));
        assert_eq!(report.unused_global.len(), 100);
        assert_eq!(report.pubsub.unwrap().recorded_pushes, 65537);
    }
}

#[tokio::test]
async fn notifications_preserve_wire_order_across_pages_and_stop_on_unsubscribe() {
    let dir = tempfile::tempdir().unwrap();
    let sub = Uuid::new_v4();
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
    let unsubscription = b"*3\r\n$11\r\nunsubscribe\r\n$4\r\njobs\r\n:0\r\n";
    let mut globals = vec![
        exchange(sub, 1, "SUBSCRIBE", &[b"jobs"], confirmation),
        exchange(sub, 2, "UNSUBSCRIBE", &[b"jobs"], unsubscription),
    ];
    let messages: Vec<_> = (0..513)
        .map(|i| crate::redis::encode_array(&[b"message", b"jobs", i.to_string().as_bytes()]))
        .collect();
    globals.extend(messages.iter().map(|raw| push(sub, None, raw, 0)));
    globals.push(push(
        sub,
        None,
        &crate::redis::encode_array(&[b"message", b"jobs", b"later"]),
        60000,
    ));
    let runtime = runtime(dir.path(), &[], &globals, true).await.unwrap();
    let (mut subscriber, task) = connect(&runtime).await;
    assert_eq!(
        send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
        confirmation
    );
    for expected in messages {
        assert_eq!(read(&mut subscriber).await, expected);
    }
    assert_eq!(
        send(&mut subscriber, &[b"UNSUBSCRIBE", b"jobs"]).await,
        unsubscription
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(30),
            read_redis_frame(&mut subscriber)
        )
        .await
        .is_err()
    );
    let state = runtime.state.lock().await;
    assert_eq!(state.redis.pubsub.indexed.delivered, 513);
    assert_eq!(state.redis.pubsub.global_unused_count(), 1);
    assert!(state.redis.events.unsafe_events.is_empty());
    task.abort();
}
