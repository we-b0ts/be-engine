//! Explicit identity formats compose with native RPC and strict broadcast rooms.
use super::*;

const SOURCE_SID: &str = "sourceSID0123456789a";
const TARGET_SID: &str = "targetSID0123456";

fn rpc_payload(host: &str, sid: &str) -> Value {
    let mut value: Value = serde_json::from_slice(&request(host, 1)).unwrap();
    value["room"] = sid.into();
    value["callback"][0] = sid.into();
    value
}

#[tokio::test]
async fn rpc_sid_representation_requires_explicit_formats_without_relaxing_business_rooms() {
    assert_eq!(SOURCE_SID.len(), 20);
    assert_eq!(TARGET_SID.len(), 16);
    for lazy in [false, true] {
        for (format, accepted) in [("{base64url: 20}", false), ("string", true)] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path();
            std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
            std::fs::create_dir_all(root.join("case")).unwrap();
            std::fs::write(
                root.join("case/request.json"),
                r#"{"method":"GET","uri":"/socket.io/"}"#,
            )
            .unwrap();
            std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
            std::fs::write(
                root.join(".traffic-e2e/policy.yaml"),
                format!(
                    "format: traffic-policy/v3\njson:\n  fields:\n    /host_id: {{kind: identity, formats: [{{hex: 32}}]}}\n    /room: {{kind: identity, formats: [{format}]}}\n    /callback/0: {{kind: identity, formats: [{format}]}}\n"
                ),
            )
            .unwrap();
            let mut source_broadcast = rpc_payload(SOURCE, SOURCE_SID);
            source_broadcast["callback"] = Value::Null;
            source_broadcast["room"] = "user:7".into();
            let mut actual_broadcast = source_broadcast.clone();
            actual_broadcast["host_id"] = TARGET.into();
            let publisher = Uuid::new_v4();
            let source_rpc = serde_json::to_vec(&rpc_payload(SOURCE, SOURCE_SID)).unwrap();
            let mut rpc = exchange(publisher, 2, "PUBLISH", &[b"jobs", &source_rpc], b":1\r\n");
            rpc["rpc_callback_capture"] = "bounded_window".into();
            let runtime = runtime(
                root,
                &[
                    exchange(
                        publisher,
                        1,
                        "PUBLISH",
                        &[b"jobs", &serde_json::to_vec(&source_broadcast).unwrap()],
                        b":1\r\n",
                    ),
                    rpc,
                ],
                &[],
                lazy,
            )
            .await
            .unwrap();
            let (mut client, mut task) = connect(&runtime).await;
            let mut changed = actual_broadcast.clone();
            changed["room"] = "user:8".into();
            send_unmatched(
                &mut client,
                &[b"PUBLISH", b"jobs", &serde_json::to_vec(&changed).unwrap()],
            )
            .await;
            reconnect(&runtime, &mut client, &mut task).await;
            assert_eq!(
                send(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&actual_broadcast).unwrap()
                    ]
                )
                .await,
                b":1\r\n"
            );
            let actual_rpc = rpc_payload(TARGET, TARGET_SID);
            for (pointer, value) in [
                ("/room", json!("another-sid")),
                ("/data/0/argv", json!(["changed-command"])),
                ("/host_id", json!(Uuid::new_v4().simple().to_string())),
            ] {
                let mut changed = actual_rpc.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                send_unmatched(
                    &mut client,
                    &[b"PUBLISH", b"jobs", &serde_json::to_vec(&changed).unwrap()],
                )
                .await;
                reconnect(&runtime, &mut client, &mut task).await;
            }
            if accepted {
                let response = send(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&actual_rpc).unwrap(),
                    ],
                )
                .await;
                assert_eq!(response, b":1\r\n", "lazy={lazy}");
                assert!(
                    runtime
                        .state
                        .lock()
                        .await
                        .protocols
                        .redis
                        .snapshot()
                        .unused_case
                        .is_empty()
                );
                send_unmatched(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&actual_rpc).unwrap(),
                    ],
                )
                .await;
            } else {
                send_unmatched(
                    &mut client,
                    &[
                        b"PUBLISH",
                        b"jobs",
                        &serde_json::to_vec(&actual_rpc).unwrap(),
                    ],
                )
                .await;
            }
            task.abort();
        }
    }
}
