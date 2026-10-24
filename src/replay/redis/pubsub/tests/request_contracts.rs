//! Real RPC/ACK transport with explicitly scoped generated payload fields.
use super::*;

fn payload(host: &str, id: u64, now: chrono::DateTime<chrono::Utc>, signature: char) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&request(host, id)).unwrap();
    value["data"][0]["plugins"] = json!([
        {"name":"first","download_path":format!("https://storage.test/bucket/first?X-Amz-Date={}&X-Amz-Signature={}&X-Amz-Expires=3600",now.format("%Y%m%dT%H%M%SZ"),signature.to_string().repeat(64)),"expires_at":now.timestamp()+3600},
        {"name":"second","download_path":format!("https://storage.test/bucket/second?X-Amz-Date={}&X-Amz-Signature={}&X-Amz-Expires=3600",now.format("%Y%m%dT%H%M%SZ"),signature.to_string().repeat(64)),"expires_at":now.timestamp()+3600},
    ]);
    for plugin in value["data"][0]["plugins"].as_array_mut().unwrap() {
        plugin["download_path"] = format!(
            "{}&X-Amz-Credential=access%2F{}%2Fregion%2Fs3%2Faws4_request",
            plugin["download_path"].as_str().unwrap(),
            now.format("%Y%m%d")
        )
        .into();
    }
    serde_json::to_vec(&value).unwrap()
}

fn policy() -> Value {
    json!({"format":"traffic-policy/v2","rules":[{
        "id":"rpc-downloads","match":{"api":"POST /scenario","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"key":{"kind":"exact","value":"jobs"}},
        "effect":{"kind":"redis_sequence","commands":[{"operation":"PUBLISH","arguments":{"1":{"kind":"json","fields":{
            "/data/0/plugins/*/download_path":{"kind":"url","query":{
                "X-Amz-Date":{"kind":"time","format":"amz_date","relation":"preserve_offset","clock_group":"signing"},
                "X-Amz-Signature":{"kind":"random","format":"hex","length":64}
                ,"X-Amz-Credential":{"kind":"utc_date_segment","separator":"/","index":1,"relative_to":"X-Amz-Date"}
            }},
            "/data/0/plugins/*/expires_at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset","clock_group":"expiry"}
        }}}}]},"proof":{"source":"app/downloads.py:dispatch","fact":"Source signs fresh download URLs and reads an independent expiry clock per plugin; paths, names, lifetime and RPC semantics are stable"}
    }]})
}

#[tokio::test]
async fn rpc_request_contracts_compose_with_ack_identity_and_preserve_all_other_payload_fields() {
    for lazy in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        std::fs::create_dir_all(root.join("case")).unwrap();
        std::fs::write(root.join(".traffic-e2e/policy.yaml"), policy().to_string()).unwrap();
        std::fs::write(
            root.join("case/request.json"),
            r#"{"method":"POST","uri":"/scenario","timestamp":"2020-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        std::fs::write(root.join("case/expected-response.json"), "{}").unwrap();
        let source_time = "2020-01-01T00:00:00Z".parse().unwrap();
        let source_request = payload(SOURCE, 1, source_time, 'a');
        let subscriber_id = Uuid::new_v4();
        let publisher = Uuid::new_v4();
        let confirmed = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
        let raw = crate::redis::encode_array(&[b"message", b"jobs", &callback(SOURCE, 1)]);
        let mut published = exchange(
            publisher,
            1,
            "PUBLISH",
            &[b"jobs", &source_request],
            b":2\r\n",
        );
        published["timestamp"] = "2020-01-01T00:00:00Z".into();
        let records = vec![published, push(subscriber_id, Some(publisher), &raw, 0)];
        let compiled = crate::policy::compile_policy(
            &crate::policy::parse_policy(&policy().to_string()).unwrap(),
        )
        .unwrap();
        let request = json!({"method":"POST","uri":"/scenario","timestamp":"2020-01-01T00:00:00Z"});
        let selected = std::collections::BTreeSet::from(["rpc-downloads".to_owned()]);
        let dir = root.join("case");
        let checked = crate::replay::validate_native_source_dependencies(
            &compiled,
            &selected,
            root,
            &[crate::replay::NativeSourceCase {
                id: "case",
                dir: &dir,
                request: &request,
                events: &records,
            }],
        )
        .unwrap();
        assert_eq!(checked.rules["rpc-downloads"], 1);
        assert!(
            crate::replay::validate_native_source_dependencies(
                &compiled,
                &selected,
                root,
                &[crate::replay::NativeSourceCase {
                    id: "case",
                    dir: &dir,
                    request: &request,
                    events: &records[..1]
                }]
            )
            .is_err()
        );
        let runtime = runtime(
            root,
            &records,
            &[exchange(
                subscriber_id,
                1,
                "SUBSCRIBE",
                &[b"jobs"],
                confirmed,
            )],
            lazy,
        )
        .await
        .unwrap();
        let (mut subscriber, sub_task) = connect(&runtime).await;
        let (mut client, client_task) = connect(&runtime).await;
        assert_eq!(
            send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
            confirmed
        );
        let now = chrono::Utc::now();
        let actual = payload(TARGET, 9, now, 'b');
        let valid: Value = serde_json::from_slice(&actual).unwrap();
        for (pointer, wrong) in [
            ("/event", json!("different:event")),
            ("/data/0/argv", json!(["changed-command"])),
            ("/data/0/plugins/0/name", json!("different")),
            (
                "/data/0/plugins/0/expires_at",
                json!(now.timestamp() + 9999),
            ),
            (
                "/data/0/plugins/0/download_path",
                json!(format!(
                    "https://storage.test/bucket/changed?X-Amz-Date={}&X-Amz-Signature={}&X-Amz-Expires=3600",
                    now.format("%Y%m%dT%H%M%SZ"),
                    "b".repeat(64)
                )),
            ),
            (
                "/data/0/plugins/0/download_path",
                json!(format!(
                    "https://storage.test/bucket/first?X-Amz-Date={}&X-Amz-Signature={}&X-Amz-Expires=7200",
                    now.format("%Y%m%dT%H%M%SZ"),
                    "b".repeat(64)
                )),
            ),
            (
                "/data/0/plugins/0/download_path",
                json!(format!(
                    "https://storage.test/bucket/first?X-Amz-Date={}&X-Amz-Signature=invalid&X-Amz-Expires=3600",
                    now.format("%Y%m%dT%H%M%SZ")
                )),
            ),
            (
                "/data/0/plugins/0/download_path",
                json!(format!(
                    "https://storage.test/bucket/first?X-Amz-Date=20200101T000000Z&X-Amz-Signature={}&X-Amz-Expires=3600",
                    "b".repeat(64)
                )),
            ),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong;
            changed["host_id"] = "11111111111141118111111111111111".into();
            assert!(
                send(
                    &mut client,
                    &[b"PUBLISH", b"jobs", &serde_json::to_vec(&changed).unwrap()]
                )
                .await
                .starts_with(b"-ERR"),
                "accepted {pointer}, lazy={lazy}"
            );
        }
        assert_eq!(
            send(&mut client, &[b"PUBLISH", b"jobs", &actual]).await,
            b":2\r\n"
        );
        let raw = read(&mut subscriber).await;
        let frame = parse_pubsub_push(&raw).unwrap().unwrap();
        let (identity, result) = rpc::callback(&frame.payload).unwrap().unwrap();
        assert_eq!((identity.host.as_str(), identity.id), (TARGET, 9));
        assert_eq!(result["args"][0]["stdout"], "example result");
        assert!(
            send(&mut client, &[b"PUBLISH", b"jobs", &actual])
                .await
                .starts_with(b"-ERR")
        );
        let state = runtime.state.lock().await;
        let snapshot = state.redis.snapshot();
        assert!(snapshot.unused_case.is_empty());
        assert_eq!(snapshot.pubsub.unwrap().delivered_rpc_callbacks, 1);
        assert!(
            state
                .replay_policy
                .as_ref()
                .unwrap()
                .report()
                .dependency_rules
                .iter()
                .any(|r| r.id == "rpc-downloads" && r.matches == 1 && r.time_validations == 4)
        );
        sub_task.abort();
        client_task.abort();
    }
}
