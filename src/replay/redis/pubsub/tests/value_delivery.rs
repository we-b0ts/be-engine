//! Genuine Pub/Sub input uses selected formats and accepted request identities.
use super::*;

const ACK: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
const INPUT: &[u8] = br#"{ "payload" : { "client_id" : "historical-token", "fixed" : "historical-token" }, "literal":17 }"#;

fn policy(root: &Path, selected: bool) {
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::write(
        root.join("case/request.json"),
        r#"{"method":"GET","uri":"/"}"#,
    )
    .unwrap();
    std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
    let mut fields = serde_json::Map::new();
    fields.insert(
        "/request_id".into(),
        json!({"kind":"identity","formats":["string"]}),
    );
    if selected {
        fields.insert(
            "/payload/client_id".into(),
            json!({"kind":"identity","formats":["string"]}),
        );
    }
    std::fs::write(
        root.join(".traffic-e2e/policy.yaml"),
        json!({"format":"traffic-policy/v3","json":{"fields":fields}}).to_string(),
    )
    .unwrap();
}

#[tokio::test]
async fn ordinary_json_push_derives_only_selected_committed_identities_over_real_tcp() {
    for lazy in [false, true] {
        for selected in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            policy(temp.path(), selected);
            let subscriber = Uuid::new_v4();
            let source = br#"{"request_id":"historical-token"}"#;
            let target = br#"{"request_id":"new-longer-target-token"}"#;
            let original = crate::redis::encode_array(&[b"message", b"jobs", INPUT]);
            let runtime = runtime(
                temp.path(),
                &[
                    exchange(Uuid::new_v4(), 1, "PUBLISH", &[b"jobs", source], b":1\r\n"),
                    exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], ACK),
                    push(subscriber, None, &original, 5),
                ],
                &[],
                lazy,
            )
            .await
            .unwrap();
            let unchanged = std::fs::read(temp.path().join("case/dependencies.jsonl")).unwrap();
            let (mut publisher, publisher_task) = connect(&runtime).await;
            assert_eq!(
                send(&mut publisher, &[b"PUBLISH", b"jobs", target]).await,
                b":1\r\n"
            );
            let (mut input, input_task) = connect(&runtime).await;
            assert_eq!(send(&mut input, &[b"SUBSCRIBE", b"jobs"]).await, ACK);
            let received = read(&mut input).await;
            let expected = if selected {
                br#"{ "payload" : { "client_id" : "new-longer-target-token", "fixed" : "historical-token" }, "literal":17 }"#.as_slice()
            } else {
                INPUT
            };
            assert_eq!(
                received,
                crate::redis::encode_array(&[b"message", b"jobs", expected])
            );
            assert_eq!(
                std::fs::read(temp.path().join("case/dependencies.jsonl")).unwrap(),
                unchanged
            );
            let state = runtime.state.lock().await;
            assert!(state.redis.snapshot().unmatched.is_empty());
            assert!(state.redis.snapshot().unused_case.is_empty());
            assert_eq!(state.redis.pubsub.report().unwrap().delivered_pushes, 1);
            publisher_task.abort();
            input_task.abort();
        }
    }
}

#[tokio::test]
async fn an_unknown_selected_notification_identity_stays_an_exact_input_anchor() {
    let temp = tempfile::tempdir().unwrap();
    policy(temp.path(), true);
    let subscriber = Uuid::new_v4();
    let original = crate::redis::encode_array(&[b"message", b"jobs", INPUT]);
    let runtime = runtime(
        temp.path(),
        &[
            exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], ACK),
            push(subscriber, None, &original, 5),
        ],
        &[],
        true,
    )
    .await
    .unwrap();
    let (mut input, task) = connect(&runtime).await;
    assert_eq!(send(&mut input, &[b"SUBSCRIBE", b"jobs"]).await, ACK);
    assert_eq!(read(&mut input).await, original);
    let state = runtime.state.lock().await;
    let owner = &state.redis.request_contracts;
    assert!(
        owner
            .knows_identity_value(
                "case",
                &json!("historical-token"),
                &json!("historical-token")
            )
            .unwrap()
    );
    assert!(
        owner
            .preview_identity_pairs(
                "case",
                &[crate::value_contract::identities::IdentityPair {
                    source: json!("historical-token").to_string(),
                    target: json!("new-token").to_string(),
                }]
            )
            .is_err()
    );
    task.abort();
}
