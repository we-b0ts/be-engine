use super::*;

fn subscription(connection: Uuid, sequence: u64) -> Value {
    let mut record = exchange(
        connection,
        sequence,
        "SUBSCRIBE",
        &[b"jobs"],
        b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n",
    );
    record["id"] = json!(Uuid::new_v4());
    record
}

fn mirror(original: &Value) -> Value {
    let mut copy = original.clone();
    copy["global_dependency_reason"] = json!("pubsub_subscription_mirror");
    copy
}

fn notification(connection: Uuid, sequence: u64, delay: u64) -> Value {
    let mut record = push(
        connection,
        None,
        &crate::redis::encode_array(&[b"message", b"jobs", b"notification"]),
        delay,
    );
    record["subscription_sequence"] = json!(sequence);
    record
}

async fn foreign_runtime(
    root: &Path,
    foreign: &[Value],
    globals: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    tokio::fs::create_dir_all(root.join("case")).await?;
    tokio::fs::create_dir_all(root.join("foreign")).await?;
    let jsonl = |records: &[Value]| records.iter().map(|v| format!("{v}\n")).collect::<String>();
    tokio::fs::write(root.join("case/dependencies.jsonl"), "").await?;
    tokio::fs::write(root.join("foreign/dependencies.jsonl"), jsonl(foreign)).await?;
    tokio::fs::write(root.join("global-dependencies.jsonl"), jsonl(globals)).await?;
    tokio::fs::write(
        root.join("recording-run.json"),
        r#"{"run_id":"subscription-test","status":"completed"}"#,
    )
    .await?;
    load_runtime(root, lazy).await
}

#[tokio::test]
async fn selected_subscription_mirror_and_startup_alias_share_one_case_slot() {
    for lazy in [false, true] {
        for startup_first in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let connection = Uuid::new_v4();
            let original = subscription(connection, 1);
            let runtime = runtime(
                temp.path(),
                &[
                    original.clone(),
                    exchange(Uuid::new_v4(), 1, "GET", &[b"private"], b"$1\r\nv\r\n"),
                ],
                &[
                    mirror(&original),
                    notification(connection, 1, 10),
                    notification(connection, 1, 50),
                ],
                lazy,
            )
            .await
            .unwrap();
            if startup_first {
                runtime.state.lock().await.active_case_id = None;
            }
            let (mut client, task) = connect(&runtime).await;
            assert_eq!(
                send(&mut client, &[b"SUBSCRIBE", b"jobs"]).await,
                b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n"
            );
            let first = read(&mut client).await;
            runtime.state.lock().await.active_case_id = Some("another-case".into());
            assert_eq!(
                read(&mut client).await,
                first,
                "process subscription survives Case changes"
            );
            assert!(
                send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                    .await
                    .starts_with(b"-ERR")
            );
            let state = runtime.state.lock().await;
            assert_eq!(state.redis.exchanges.len(), 2, "mirror added no slot");
            assert_eq!(state.redis.exchanges[0].source, ReplaySource::Case);
            assert_eq!(state.redis.exchanges[0].case_id.as_deref(), Some("case"));
            assert!(state.redis.exchanges[0].status.is_consumed());
            let report = &state.redis.events.matched[0];
            assert_eq!(report.source, ReplaySource::Case);
            assert_eq!(report.case_id.as_deref(), Some("case"));
            assert_eq!(
                state.redis.snapshot().unused_case.len(),
                1,
                "business GET remains finite and private"
            );
            assert_eq!(state.redis.events.matched_count, 1);
            task.abort();
        }
    }
}

#[tokio::test]
async fn foreign_case_lookup_loads_only_exact_referenced_control_evidence() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let runtime = foreign_runtime(
            temp.path(),
            &[
                exchange(
                    connection,
                    1,
                    "CLIENT",
                    &[b"SETINFO", b"LIB-NAME", b"redis-py"],
                    b"+OK\r\n",
                ),
                subscription(connection, 4),
                exchange(
                    Uuid::new_v4(),
                    1,
                    "PUBLISH",
                    &[b"jobs", &request(SOURCE, 1)],
                    b":1\r\n",
                ), // Loading this unrelated orphan RPC would fail.
            ],
            &[notification(connection, 4, 10)],
            lazy,
        )
        .await
        .unwrap();
        runtime.state.lock().await.active_case_id = None;
        {
            let state = runtime.state.lock().await;
            assert_eq!(state.redis.exchanges.len(), 1);
            assert_eq!(state.redis.exchanges[0].record.command, "SUBSCRIBE");
            assert_eq!(state.redis.exchanges[0].record.sequence, 4);
        }
        let (mut client, task) = connect(&runtime).await;
        assert!(
            !send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        read(&mut client).await;
        assert!(
            send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        task.abort();
    }
}

#[tokio::test]
async fn mirror_without_selected_original_provides_one_exact_global_control_slot() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let original = subscription(connection, 1);
        let runtime = runtime(
            temp.path(),
            &[],
            &[mirror(&original), notification(connection, 1, 10)],
            lazy,
        )
        .await
        .unwrap();
        runtime.state.lock().await.active_case_id = None;
        let (mut client, task) = connect(&runtime).await;
        assert!(
            !send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        read(&mut client).await;
        assert!(
            send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        assert_eq!(runtime.state.lock().await.redis.exchanges.len(), 1);
        task.abort();
    }
}

#[tokio::test]
async fn unreferenced_mirror_does_not_promote_a_case_command_to_global() {
    let temp = tempfile::tempdir().unwrap();
    let original = subscription(Uuid::new_v4(), 1);
    let runtime = runtime(
        temp.path(),
        std::slice::from_ref(&original),
        &[mirror(&original)],
        true,
    )
    .await
    .unwrap();
    runtime.state.lock().await.active_case_id = None;
    let (mut client, task) = connect(&runtime).await;
    assert!(
        send(&mut client, &[b"SUBSCRIBE", b"jobs"])
            .await
            .starts_with(b"-ERR")
    );
    assert!(!runtime.state.lock().await.redis.exchanges[0].subscription_alias);
    task.abort();
}

#[tokio::test]
async fn subscription_alias_preserves_selected_case_lane_barriers() {
    let temp = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let original = subscription(connection, 2);
    let runtime = runtime(
        temp.path(),
        &[
            exchange(connection, 1, "GET", &[b"private"], b"$1\r\nv\r\n"),
            original.clone(),
        ],
        &[mirror(&original), notification(connection, 2, 10)],
        true,
    )
    .await
    .unwrap();
    runtime.state.lock().await.active_case_id = None;
    let (mut client, task) = connect(&runtime).await;
    assert!(
        send(&mut client, &[b"SUBSCRIBE", b"jobs"])
            .await
            .starts_with(b"-ERR")
    );
    runtime.state.lock().await.active_case_id = Some("case".into());
    assert_eq!(
        send(&mut client, &[b"GET", b"private"]).await,
        b"$1\r\nv\r\n"
    );
    assert!(
        !send(&mut client, &[b"SUBSCRIBE", b"jobs"])
            .await
            .starts_with(b"-ERR")
    );
    read(&mut client).await;
    task.abort();
}

#[tokio::test]
async fn conflicting_subscription_mirrors_are_not_aliases() {
    for mode in ["id", "confirmation", "database", "subject", "unsafe"] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let original = subscription(connection, 1);
        let mut copy = mirror(&original);
        match mode {
            "id" => copy["id"] = json!(Uuid::new_v4()),
            "confirmation" => {
                copy["response"] = capture(b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:2\r\n")
            }
            "database" => copy["database"] = json!(1),
            "subject" => copy["args"][0] = capture(b"other"),
            "unsafe" => copy["replay_safe"] = json!(false),
            _ => unreachable!(),
        }
        assert!(
            runtime(
                temp.path(),
                &[original],
                &[copy, notification(connection, 1, 10)],
                true
            )
            .await
            .is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn foreign_case_cannot_substitute_another_connection_sequence_or_session() {
    for mode in [
        "connection",
        "sequence",
        "database",
        "username",
        "duplicate",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let mut original = subscription(connection, 1);
        match mode {
            "connection" => original["connection_id"] = json!(Uuid::new_v4()),
            "sequence" => original["sequence"] = json!(2),
            "database" => original["database"] = json!(1),
            "username" => original["username"] = json!("another-user"),
            "duplicate" => {}
            _ => unreachable!(),
        }
        let mut foreign = vec![original.clone()];
        if mode == "duplicate" {
            foreign.push(original);
        }
        assert!(
            foreign_runtime(
                temp.path(),
                &foreign,
                &[notification(connection, 1, 10)],
                true
            )
            .await
            .is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn foreign_subscription_does_not_bypass_business_or_control_lane_predecessors() {
    for command in ["GET", "SUBSCRIBE", "UNSUBSCRIBE"] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let original = subscription(connection, 2);
        let predecessor = if command == "SUBSCRIBE" {
            subscription(connection, 1)
        } else {
            exchange(connection, 1, command, &[b"jobs"], b"+OK\r\n")
        };
        let error = foreign_runtime(
            temp.path(),
            &[predecessor, original],
            &[notification(connection, 2, 10)],
            true,
        )
        .await
        .err()
        .expect("foreign predecessor must remain a barrier");
        assert!(
            format!("{error:#}").contains("lane predecessor"),
            "{command}: {error:#}"
        );
    }
}

#[tokio::test]
async fn conflicting_foreign_subscription_identity_is_not_hidden_by_request_key() {
    let temp = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let original = subscription(connection, 1);
    let mut conflict = original.clone();
    conflict["args"][0] = capture(b"other");
    conflict["response"] = capture(b"*3\r\n$9\r\nsubscribe\r\n$5\r\nother\r\n:1\r\n");
    assert!(
        foreign_runtime(
            temp.path(),
            &[conflict, original],
            &[notification(connection, 1, 10)],
            true,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn rpc_only_reconnect_uses_confirmed_mirror_without_promoting_publish() {
    for lazy in [false, true] {
        for with_mirror in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let sub = Uuid::new_v4();
            let publisher = Uuid::new_v4();
            let original = subscription(sub, 1);
            tokio::fs::create_dir_all(temp.path().join("foreign"))
                .await
                .unwrap();
            tokio::fs::write(
                temp.path().join("foreign/dependencies.jsonl"),
                format!("{original}\n"),
            )
            .await
            .unwrap();
            tokio::fs::write(
                temp.path().join("recording-run.json"),
                r#"{"run_id":"rpc-only-test","status":"completed"}"#,
            )
            .await
            .unwrap();
            let globals = if with_mirror {
                vec![mirror(&original)]
            } else {
                vec![]
            };
            let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
            let loaded = runtime(
                temp.path(),
                &[
                    exchange(
                        publisher,
                        1,
                        "PUBLISH",
                        &[b"jobs", &request(SOURCE, 1)],
                        b":1\r\n",
                    ),
                    push(sub, Some(publisher), &raw, 10),
                ],
                &globals,
                lazy,
            )
            .await;
            if !with_mirror {
                assert!(
                    loaded.is_err(),
                    "historical Case-only proof cannot grant Global RPC startup control"
                );
                continue;
            }
            let runtime = loaded.unwrap();
            runtime.state.lock().await.active_case_id = None;
            let (mut subscriber, sub_task) = connect(&runtime).await;
            assert!(
                !send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"])
                    .await
                    .starts_with(b"-ERR")
            );
            let (mut client, client_task) = connect(&runtime).await;
            assert!(
                send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)])
                    .await
                    .starts_with(b"-ERR")
            );
            runtime.state.lock().await.active_case_id = Some("case".into());
            assert_eq!(
                send(&mut client, &[b"PUBLISH", b"jobs", &request(TARGET, 9)]).await,
                b":1\r\n"
            );
            let received = read(&mut subscriber).await;
            let frame = parse_pubsub_push(&received).unwrap().unwrap();
            let (identity, _) = rpc::callback(&frame.payload).unwrap().unwrap();
            assert_eq!(identity.id, 9);
            assert!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"])
                    .await
                    .starts_with(b"-ERR")
            );
            let state = runtime.state.lock().await;
            assert_eq!(state.redis.exchanges.len(), 2);
            assert_eq!(
                state
                    .redis
                    .exchanges
                    .iter()
                    .filter(|exchange| exchange.source == ReplaySource::Case)
                    .count(),
                1
            );
            assert_eq!(
                state.redis.pubsub.report().unwrap().delivered_rpc_callbacks,
                1
            );
            client_task.abort();
            sub_task.abort();
        }
    }
}

#[tokio::test]
async fn retained_mirror_survives_failed_or_unpublished_original_case() {
    for unpublished in ["failed", "staging"] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let original = subscription(connection, 1);
        let abandoned = temp.path().join(unpublished).join("abandoned-case");
        tokio::fs::create_dir_all(&abandoned).await.unwrap();
        tokio::fs::write(
            abandoned.join("dependencies.jsonl"),
            format!("{original}\n"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            temp.path().join("recording-run.json"),
            r#"{"run_id":"failed-case-test","status":"completed"}"#,
        )
        .await
        .unwrap();
        let runtime = runtime(
            temp.path(),
            &[],
            &[mirror(&original), notification(connection, 1, 10)],
            true,
        )
        .await
        .unwrap();
        runtime.state.lock().await.active_case_id = None;
        let (mut client, task) = connect(&runtime).await;
        assert!(
            !send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        read(&mut client).await;
        assert!(
            send(&mut client, &[b"SUBSCRIBE", b"jobs"])
                .await
                .starts_with(b"-ERR")
        );
        let state = runtime.state.lock().await;
        assert_eq!(state.redis.events.matched_count, 1);
        assert_eq!(state.redis.global_unused_count(), 0);
        task.abort();
    }
}

#[tokio::test]
async fn indexed_foreign_lookup_preserves_pattern_and_shard_subscription_kinds() {
    for (command, confirmation, push_kind) in [
        (
            "PSUBSCRIBE",
            b"*3\r\n$10\r\npsubscribe\r\n$4\r\njobs\r\n:1\r\n".as_slice(),
            "pmessage",
        ),
        (
            "SSUBSCRIBE",
            b"*3\r\n$10\r\nssubscribe\r\n$4\r\njobs\r\n:1\r\n".as_slice(),
            "smessage",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let connection = Uuid::new_v4();
        let original = exchange(connection, 4, command, &[b"jobs"], confirmation);
        let raw = if push_kind == "pmessage" {
            crate::redis::encode_array(&[b"pmessage", b"jobs", b"jobs", b"notification"])
        } else {
            crate::redis::encode_array(&[b"smessage", b"jobs", b"notification"])
        };
        let mut notification = push(connection, None, &raw, 10);
        notification["subscription_sequence"] = json!(4);
        let runtime = foreign_runtime(temp.path(), &[original], &[notification], true)
            .await
            .unwrap();
        runtime.state.lock().await.active_case_id = None;
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut client, &[command.as_bytes(), b"jobs"]).await,
            confirmation
        );
        assert_eq!(read(&mut client).await, raw);
        assert_eq!(runtime.state.lock().await.redis.global_unused_count(), 0);
        task.abort();
    }
}
