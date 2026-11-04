//! A generated subscription identity also owns the channel on incoming frames.
use super::*;

fn confirmation(command: &str, subject: &[u8], count: u8) -> Vec<u8> {
    let mut bytes = format!(
        "*3\r\n${}\r\n{command}\r\n${}\r\n",
        command.len(),
        subject.len()
    )
    .into_bytes();
    bytes.extend_from_slice(subject);
    bytes.extend_from_slice(format!("\r\n:{count}\r\n").as_bytes());
    bytes
}

#[tokio::test]
async fn generated_channel_identity_reaches_every_notification_and_unsubscribe_over_tcp() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        std::fs::create_dir_all(root.join("case")).unwrap();
        std::fs::write(
            root.join("case/request.json"),
            r#"{"method":"GET","uri":"/"}"#,
        )
        .unwrap();
        std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
        std::fs::write(
            root.join(".traffic-e2e/policy.yaml"),
            r#"format: traffic-policy/v3
redis:
  keys:
    jobs:*:
      key_format: {kind: identity, formats: [{hex: 8}]}
      commands: [SUBSCRIBE, UNSUBSCRIBE]
"#,
        )
        .unwrap();
        let subscriber = Uuid::new_v4();
        let source = b"jobs:aabbccdd";
        let target = b"jobs:11223344";
        // Include the original channel bytes in the opaque payload: this must
        // translate routing metadata only, never a substring inside the value.
        let payload = b"\0jobs:aabbccdd\r\n\xff";
        let raw = crate::redis::encode_array(&[b"message", source, payload]);
        let runtime = runtime(
            root,
            &[
                exchange(
                    subscriber,
                    1,
                    "SUBSCRIBE",
                    &[source],
                    &confirmation("subscribe", source, 1),
                ),
                push(subscriber, None, &raw, 5),
                exchange(
                    subscriber,
                    2,
                    "UNSUBSCRIBE",
                    &[source],
                    &confirmation("unsubscribe", source, 0),
                ),
            ],
            &[],
            lazy,
        )
        .await
        .unwrap();
        let original = std::fs::read(root.join("case/dependencies.jsonl")).unwrap();
        let (mut client, task) = connect(&runtime).await;
        assert_eq!(
            send(&mut client, &[b"SUBSCRIBE", target]).await,
            confirmation("subscribe", target, 1)
        );
        assert_eq!(
            read(&mut client).await,
            crate::redis::encode_array(&[b"message", target, payload])
        );
        assert_eq!(
            send(&mut client, &[b"UNSUBSCRIBE", target]).await,
            confirmation("unsubscribe", target, 0)
        );
        assert_eq!(
            std::fs::read(root.join("case/dependencies.jsonl")).unwrap(),
            original
        );
        let replay = runtime.state.lock().await;
        assert!(replay.redis.snapshot().unmatched.is_empty());
        assert!(replay.redis.snapshot().unused_case.is_empty());
        assert_eq!(replay.redis.pubsub.report().unwrap().delivered_pushes, 1);
        task.abort();
    }
}
