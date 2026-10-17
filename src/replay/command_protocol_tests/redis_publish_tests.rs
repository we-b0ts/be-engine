//! Actual RESP authoring and replay; includes opaque binary payloads.
use super::*;
use crate::{RedisPublishFeedback, RedisPublishSelector, plan_redis_publish};
use redis_value_tests::spawn;
const SOURCE_A: &str = "0123456789ab4def8123456789abcdef";
const SOURCE_B: &str = "1123456789ab4def8123456789abcdef";
const TARGET_A: &str = "fedcba98765443218123456789abcdef";
const TARGET_B: &str = "eedcba98765443218123456789abcdef";
const ERROR: &[u8] = b"-ERR no recorded Redis dependency matched\r\n";

fn payload(binary: bool, id: &str, stage: u8) -> Vec<u8> {
    if binary {
        // Pickle protocol 4 dict containing a textual UUID. Replay treats the
        // framing and all other bytes as opaque; it never executes pickle.
        let mut bytes = b"\x80\x04}\x94(\x8c\x07host_id\x94\x8c\x20".to_vec();
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(b"\x94\x8c\x05stage\x94K");
        bytes.extend_from_slice(&[stage, b'u', b'.']);
        bytes
    } else {
        format!("{{\"host_id\":\"{id}\",\"stage\":{stage}}}").into_bytes()
    }
}

fn field_payload(binary: bool, id: &str, stage: u8) -> Vec<u8> {
    let bytes = payload(binary, id, stage);
    if stage == 2 {
        if binary {
            let mut output = b"\x80\x04}\x94(\x8c\x05other\x94\x8c\x20".to_vec();
            output.extend_from_slice(SOURCE_B.as_bytes());
            output.extend_from_slice(b"\x94\x8c\x07host_id\x94\x8c\x20");
            output.extend_from_slice(id.as_bytes());
            output.extend_from_slice(b"\x94\x8c\x05stage\x94K\x02u.");
            output
        } else {
            format!("{{\"other\":\"{SOURCE_B}\",\"host_id\":\"{id}\",\"stage\":{stage}}}")
                .into_bytes()
        }
    } else {
        bytes
    }
}

#[tokio::test]
async fn redis_publish_uuid_field_preserves_other_uuids_when_payload_positions_change() {
    for binary in [false, true] {
        let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
        let case = temp.path().join("apis/publish/case");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            temp.path().join("recording-run.json"),
            r#"{"status":"completed"}"#,
        )
        .unwrap();
        let lane = Uuid::new_v4();
        let records = [1_u8,2].map(|stage| {
            let mut record = redis_hash_dependency(lane,stage.into(),"PUBLISH",&["events","placeholder"],b":1\r\n");
            record["args"][1] = serde_json::json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(field_payload(binary,SOURCE_A,stage))});
            record["response_kind"] = "integer".into();record
        });
        std::fs::write(
            case.join("dependencies.jsonl"),
            records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"POST","uri":"/publish"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let (addr, state, task) = spawn(&case, None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        publish(
            &mut client,
            "events",
            &field_payload(binary, TARGET_A, 2),
            ERROR,
        )
        .await;
        let report = temp.path().join("replay.json");
        {
            let mut state = state.lock().await;
            state.finalized_at = Some(Utc::now());
            std::fs::write(
                &report,
                serde_json::to_vec(&state.snapshot_report()).unwrap(),
            )
            .unwrap();
        }
        task.abort();
        let policy = temp.path().join("policy.yaml");
        crate::replay::write_policy_fixture(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let feedback = RedisPublishFeedback {
            policy_path: policy.clone(),
            case_source: case.clone(),
            replay_report_path: report,
            rule_id: "publisher".into(),
            selector: RedisPublishSelector {
                host: "redis.internal".into(),
                port: 6379,
                channel: "events".into(),
                uuid_index: None,
                uuid_field: Some("host_id".into()),
            },
            source_evidence: "publisher.py:host_id uses uuid4().hex once per process".into(),
        };
        let mut wrong = feedback.clone();
        wrong.selector.uuid_field = Some("other".into());
        assert!(plan_redis_publish(wrong).is_err());
        crate::replay::policy::test_fixture::install_redis_publish(feedback).unwrap();
        let (addr, _, task) = spawn(&case, Some(policy)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        publish(
            &mut client,
            "events",
            &field_payload(binary, TARGET_A, 1),
            b":1\r\n",
        )
        .await;
        let mut wrong = field_payload(binary, TARGET_A, 2);
        let start = wrong
            .windows(SOURCE_B.len())
            .position(|bytes| bytes == SOURCE_B.as_bytes())
            .unwrap();
        wrong[start..start + SOURCE_B.len()].copy_from_slice(TARGET_B.as_bytes());
        publish(&mut client, "events", &wrong, ERROR).await;
        publish(
            &mut client,
            "events",
            &field_payload(binary, TARGET_A, 2),
            b":1\r\n",
        )
        .await;
        task.abort();
    }
}

async fn publish(client: &mut TcpStream, channel: &str, payload: &[u8], expected: &[u8]) {
    let mut bytes = b"*3\r\n$7\r\nPUBLISH\r\n".to_vec();
    for arg in [channel.as_bytes(), payload] {
        bytes.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        bytes.extend_from_slice(arg);
        bytes.extend_from_slice(b"\r\n");
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        client.write_all(&bytes).await.unwrap();
        let mut response = vec![0; expected.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected);
    })
    .await
    .expect("PUBLISH request timed out");
}

#[tokio::test]
async fn redis_publish_plan_apply_preserves_uuid_relations_order_and_finite_binary_evidence() {
    for binary in [false, true] {
        let temp = crate::replay::policy::test_fixture::managed_tempdir().unwrap();
        let case = temp.path().join("apis/publish/case");
        std::fs::create_dir_all(&case).unwrap();
        std::fs::write(
            temp.path().join("recording-run.json"),
            r#"{"status":"completed"}"#,
        )
        .unwrap();
        let lane = Uuid::new_v4();
        let records = [(SOURCE_A,1),(SOURCE_A,2),(SOURCE_B,3)].map(|(id,stage)| {
            let mut record = redis_hash_dependency(lane, stage.into(), "PUBLISH", &["events","placeholder"],format!(":{stage}\r\n").as_bytes());
            record["args"][1] = serde_json::json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(payload(binary,id,stage))});
            record["response_kind"] = "integer".into();
            record
        });
        let dependencies = case.join("dependencies.jsonl");
        std::fs::write(
            &dependencies,
            records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        let immutable = std::fs::read(&dependencies).unwrap();
        std::fs::write(
            case.join("request.json"),
            r#"{"method":"POST","uri":"/publish"}"#,
        )
        .unwrap();
        std::fs::write(case.join("expected-response.json"), "{}").unwrap();
        let (addr, state, task) = spawn(&case, None).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        publish(&mut client, "events", &payload(binary, TARGET_A, 1), ERROR).await;
        let report_path = temp.path().join("replay.json");
        {
            let mut state = state.lock().await;
            state.finalized_at = Some(Utc::now());
            let report = serde_json::to_vec(&state.snapshot_report()).unwrap();
            let evidence: Value = serde_json::from_slice(&report).unwrap();
            assert_eq!(
                evidence["redis"]["publish"]["candidates"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            let public = evidence["redis"]["publish"].to_string();
            assert!(
                !public.contains(SOURCE_A)
                    && !public.contains(TARGET_A)
                    && !public.contains("host_id")
            );
            std::fs::write(&report_path, report).unwrap();
        }
        task.abort();
        let policy_path = temp.path().join("policy.yaml");
        let original_policy =
            "# keep\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\n";
        crate::replay::write_policy_fixture(&policy_path, original_policy).unwrap();
        let feedback = RedisPublishFeedback {
            policy_path: policy_path.clone(),
            case_source: case.clone(),
            replay_report_path: report_path,
            rule_id: "publisher".into(),
            selector: RedisPublishSelector {
                host: "redis.internal".into(),
                port: 6379,
                channel: "events".into(),
                uuid_index: Some(0),
                uuid_field: None,
            },
            source_evidence: "publisher.py:host_id is uuid4().hex generated once per publisher"
                .into(),
        };
        let error = plan_redis_publish(feedback.clone()).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("legacy rule authoring is retired")
        );
        crate::replay::policy::test_fixture::install_redis_publish(feedback).unwrap();
        assert_eq!(std::fs::read(&dependencies).unwrap(), immutable);
        let (addr, state, task) = spawn(&case, Some(policy_path)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut second = TcpStream::connect(addr).await.unwrap();
        // Failed previews and lane blockers cannot bind a publisher identity.
        publish(&mut client, "events", &payload(binary, TARGET_B, 3), ERROR).await;
        publish(&mut client, "other", &payload(binary, TARGET_B, 1), ERROR).await;
        publish(
            &mut client,
            "events",
            &payload(binary, "not-a-uuid", 1),
            ERROR,
        )
        .await;
        publish(
            &mut client,
            "events",
            &payload(binary, TARGET_A, 1),
            b":1\r\n",
        )
        .await;
        publish(&mut second, "events", &payload(binary, TARGET_B, 2), ERROR).await;
        publish(
            &mut second,
            "events",
            &payload(binary, TARGET_A, 2),
            b":2\r\n",
        )
        .await;
        publish(&mut second, "events", &payload(binary, TARGET_A, 3), ERROR).await;
        publish(
            &mut second,
            "events",
            &payload(binary, TARGET_B, 3),
            b":3\r\n",
        )
        .await;
        publish(&mut second, "events", &payload(binary, TARGET_B, 3), ERROR).await;
        let report = serde_json::to_value(state.lock().await.snapshot_report()).unwrap();
        assert_eq!(report["redis"]["matched_count"], 3);
        assert!(
            report["redis"]["unused_case"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            report["replay_policy"]["dependency_rules"][0]["validations"],
            3
        );
        assert_eq!(std::fs::read(dependencies).unwrap(), immutable);
        task.abort();
    }
}
