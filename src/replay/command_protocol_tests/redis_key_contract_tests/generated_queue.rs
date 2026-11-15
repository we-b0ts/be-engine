//! Celery-shaped requests retain the result-channel/task correlation over real TCP.
use super::*;

fn message(id: &str, tag: &str, reply: &str, origin: &str) -> String {
    json!({"body":"unchanged-task-body","headers":{"id":id,"root_id":id,"origin":origin,"task":"index.document"},
        "properties":{"correlation_id":id,"delivery_tag":tag,"reply_to":reply,"delivery_mode":2}}).to_string()
}

#[tokio::test]
async fn generated_queue_identities_subscribe_lpush_unsubscribe_with_strict_task_references() {
    for negative in [true, false] {
        let source_id = Uuid::new_v4().to_string();
        let actual_id = Uuid::new_v4().to_string();
        let source_key = format!("celery-task-meta-{source_id}");
        let actual_key = format!("celery-task-meta-{actual_id}");
        let source_message = message(
            &source_id,
            &Uuid::new_v4().to_string(),
            "6fa459ea-ee8a-3ca4-894e-db77e160355e",
            "gen123@source",
        );
        let subscription = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        // Subscription confirmations contain integer counts, rather than bulk strings.
        let confirmation = |kind: &str, key: &str, count: u8| {
            format!(
                "*3\r\n${}\r\n{kind}\r\n${}\r\n{key}\r\n:{count}\r\n",
                kind.len(),
                key.len()
            )
            .into_bytes()
        };
        let confirmed = confirmation("subscribe", &source_key, 1);
        let unsubscribed = confirmation("unsubscribe", &source_key, 0);
        let mut records = vec![
            redis_hash_dependency(subscription, 1, "SUBSCRIBE", &[&source_key], &confirmed),
            redis_hash_dependency(
                publisher,
                1,
                "LPUSH",
                &["celery", &source_message],
                b":1\r\n",
            ),
            redis_hash_dependency(
                subscription,
                2,
                "UNSUBSCRIBE",
                &[&source_key],
                &unsubscribed,
            ),
        ];
        for (index, record) in records.iter_mut().enumerate() {
            record["response_kind"] = if index == 1 { "integer" } else { "array" }.into();
        }
        let f = Fixture::new(records);
        f.install("result-channel",json!({"key":{"prefix":"celery-task-meta-"},
            "key_contract":{"kind":"capture","template":"celery-task-meta-{value}","format":{"kind":"uuid_v4"}},
            "commands":[{"command":"SUBSCRIBE","argument_values":{}},{"command":"UNSUBSCRIBE","argument_values":{}}]})).unwrap();
        f.install(
            "task-message",
            json!({"key":"celery","commands":[{"command":"LPUSH","argument_values":{"1":{"json":{
                "/headers/id":{"identity":{"template":"{value}"}},
                "/headers/root_id":{"identity":{"template":"{value}"}},
                "/properties/correlation_id":{"identity":{"template":"{value}"}},
                "/properties/delivery_tag":{"random":{"format":"uuid","length":36}},
                "/properties/reply_to":{"random":{"format":"uuid","length":36}},
                "/headers/origin":{"random":{"format":"string","max_length":255}}
            }}}}]}),
        )
        .unwrap();
        let (addr, state, task) = redis_value_tests::spawn(&f.case, Some(f.policy.clone())).await;
        let mut subscriber = TcpStream::connect(addr).await.unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let target_message = message(
            &actual_id,
            &Uuid::new_v4().to_string(),
            "2ed6657d-e927-368b-95e1-2665a8aea6a2",
            "gen45678@target-host-longer",
        );
        let error = b"";
        if negative {
            // A JSON reference cannot invent a missing subscription capture.
            redis_value_tests::request(&mut client, &["LPUSH", "celery", &target_message], error)
                .await;
            client = TcpStream::connect(addr).await.unwrap();
        }
        redis_value_tests::request(
            &mut subscriber,
            &["SUBSCRIBE", &actual_key],
            &confirmation("subscribe", &actual_key, 1),
        )
        .await;
        if negative {
            let valid: Value = serde_json::from_str(&target_message).unwrap();
            for (pointer, wrong) in [
                (
                    "/properties/correlation_id",
                    json!(Uuid::new_v4().to_string()),
                ),
                ("/properties/delivery_tag", json!("invalid-uuid")),
                ("/headers/origin", json!("x".repeat(256))),
                ("/headers/origin", json!("contains\ncontrol")),
                ("/body", json!("changed-task-body")),
                ("/headers/task", json!("different.task")),
            ] {
                let mut changed = valid.clone();
                *changed.pointer_mut(pointer).unwrap() = wrong;
                redis_value_tests::request(
                    &mut client,
                    &["LPUSH", "celery", &changed.to_string()],
                    error,
                )
                .await;
                client = TcpStream::connect(addr).await.unwrap();
            }
        }
        redis_value_tests::request(
            &mut client,
            &["LPUSH", "celery", &target_message],
            b":1\r\n",
        )
        .await;
        redis_value_tests::request(
            &mut subscriber,
            &["UNSUBSCRIBE", &actual_key],
            &confirmation("unsubscribe", &actual_key, 0),
        )
        .await;
        let mut locked = state.lock().await;
        locked.finalized_at = Some(Utc::now());
        let report = locked.snapshot_report();
        assert_eq!(report.native.protocols.redis.matched_count, 3);
        assert!(report.native.protocols.redis.unused_case.is_empty());
        if !negative {
            assert!(!report.is_dirty());
        }
        assert_eq!(
            std::fs::read_to_string(f.case.join("dependencies.jsonl")).unwrap(),
            f.immutable
        );
        task.abort();
    }
}
