use super::*;
use crate::value_contract::{json::AnchorClocks, time::ClockPair};
use serde_json::{Value, json};
mod request_clocks;

fn source_fixture_with(_request: bool, codec: &str) -> (tempfile::TempDir, ReplayPolicyRuntime) {
    use crate::replay::{ReplayCase, ReplayCaseStatus};
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    let dir = local.join("recordings/case");
    std::fs::create_dir_all(&dir).unwrap();
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        &key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("request.json"),
        json!({"method":"GET","uri":"/session","timestamp":"1970-01-01T00:16:40Z"}).to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("expected-response.json"), "{}").unwrap();
    std::fs::write(dir.join("dependencies.jsonl"), "").unwrap();
    let path = temp.path().join("policy.yaml");
    let raw = if codec.is_empty() {
        "format: traffic-policy/v3\nrules: []\n"
    } else {
        "format: traffic-policy/v3\njson:\n  fields:\n    /expires_at: {kind: time, formats: [unix_seconds]}\n"
    };
    std::fs::write(&path, raw).unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: dir.clone(),
            dependencies_path: dir.join("dependencies.jsonl"),
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let runtime = ReplayPolicyRuntime::load(&path, &cases).unwrap();
    (temp, runtime)
}

#[test]
fn native_set_matcher_accepts_authorized_payload_length_changes_and_keeps_flags_strict() {
    for (codec, source, target) in [(
        "json",
        br#"{"expires_at":127}"#.to_vec(),
        br#"{"expires_at":1127}"#.to_vec(),
    )] {
        for changed_flags in [false, true] {
            let (_temp, runtime) = source_fixture_with(true, codec);
            runtime.request_contracts.set_request_times(
                "case",
                crate::primary_protocol::assertion::RequestTimes {
                    source: DateTime::from_timestamp(1000, 0),
                    target: DateTime::from_timestamp(2000, 0),
                },
            );
            let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
            let mut event = source_event(Some(b"STORED\r\n"));
            event["command"] = "set".into();
            event["args"] = json!([
                capture(b"0"),
                capture(b"0"),
                capture(source.len().to_string().as_bytes())
            ]);
            event["value"] = capture(&source);
            let record: RecordedExchange = serde_json::from_value(event.clone()).unwrap();
            let mut state = super::super::MemcachedReplayState::default();
            state
                .register_exchange(
                    record,
                    ReplaySource::Case,
                    Some("case"),
                    &mut BTreeMap::new(),
                )
                .unwrap();
            assert_eq!(
                source_witness(&event, Surface::DependencyRequest).unwrap(),
                serde_json::to_vec(&request_envelope(&state.exchanges[0])).unwrap()
            );
            let request = MemcachedRequest {
                raw: bytes::Bytes::new(),
                command: "set".into(),
                opcode: None,
                opaque: None,
                key: Some(b"session".to_vec()),
                args: vec![
                    if changed_flags {
                        b"1".to_vec()
                    } else {
                        b"0".to_vec()
                    },
                    b"0".to_vec(),
                    target.len().to_string().into_bytes(),
                ],
                value: Some(target.clone()),
                extras: None,
                cas: None,
                quiet: false,
                noreply: false,
            };
            let target_key = TargetKey {
                host: "cache.test".into(),
                port: 11211,
            };
            let result = state.match_memcached(super::super::MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &target_key,
                wire_protocol: MemcachedWireProtocol::Text,
                request: &request,
                policy: Some(&runtime),
                observed_at: DateTime::from_timestamp(2000, 0).unwrap(),
            });
            assert_eq!(result.is_ok(), !changed_flags);
        }
    }
}

#[test]
fn initial_failure_without_rules_retains_source_and_independent_target_payloads() {
    let (temp, mut runtime) = source_fixture_with(true, "");
    let artifacts = temp.path().join(".traffic-e2e/local/runtime/attempt");
    let store = crate::policy_evidence::WitnessStore::new(&artifacts).unwrap();
    runtime
        .request_contracts
        .configure_witnesses(store.clone(), false)
        .unwrap();
    let source_value = vec![0, 255, 127];
    let target_value = vec![0, 255, 0, 127];
    let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
    let mut event = source_event(Some(b"STORED\r\n"));
    event["command"] = "set".into();
    event["value"] = capture(&source_value);
    event["args"] = json!([capture(b"7"), capture(b"0"), capture(b"3")]);
    source_observation(&runtime.request_contracts, "case", &event).unwrap();
    let mut state = super::super::MemcachedReplayState::default();
    state
        .register_exchange(
            serde_json::from_value(event).unwrap(),
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
        )
        .unwrap();
    let request = MemcachedRequest {
        raw: bytes::Bytes::new(),
        command: "set".into(),
        opcode: None,
        opaque: None,
        key: Some(b"session".to_vec()),
        args: vec![b"7".to_vec(), b"0".to_vec(), b"4".to_vec()],
        value: Some(target_value.clone()),
        extras: None,
        cas: None,
        quiet: false,
        noreply: false,
    };
    let target = TargetKey {
        host: "cache.test".into(),
        port: 11211,
    };
    assert!(
        state
            .match_memcached(super::super::MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &target,
                wire_protocol: MemcachedWireProtocol::Text,
                request: &request,
                policy: Some(&runtime),
                observed_at: DateTime::from_timestamp(2000, 0).unwrap()
            })
            .is_err()
    );
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.complete);
    let witnesses = manifest.witnesses().unwrap();
    let independent = witnesses
        .iter()
        .find(|witness| witness.metadata.target_role == TargetRole::IndependentTargetObservation)
        .unwrap();
    let path = crate::policy_evidence::verify(&artifacts.join("replay.json"), &manifest).unwrap();
    let (source_bytes, target_bytes) =
        crate::policy_evidence::read(&path, independent, &artifacts).unwrap();
    assert_eq!(
        crate::memcached::value_slot::witness_values(&source_bytes, false).unwrap(),
        vec![(b"session".to_vec(), source_value)]
    );
    assert_eq!(
        crate::memcached::value_slot::witness_values(&target_bytes.unwrap(), false).unwrap(),
        vec![(b"session".to_vec(), target_value)]
    );
    assert!(runtime.report().dependency_rules.is_empty());
}

fn witness_clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
        delivery: ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2005, 0),
        },
        ..Default::default()
    }
}

#[test]
fn native_request_witness_guard_accepts_only_value_lengths_and_native_expiration() {
    let source_value = br#"{"expires_at":127}"#;
    let target_value = br#"{"expires_at":1127}"#;
    let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
    let mut event = source_event(Some(b"STORED\r\n"));
    event["command"] = "set".into();
    event["value"] = capture(source_value);
    event["args"] = json!([
        capture(b"7"),
        capture(b"0"),
        capture(source_value.len().to_string().as_bytes())
    ]);
    let source = source_witness(&event, Surface::DependencyRequest).unwrap();
    let mut target: serde_json::Value = serde_json::from_slice(&source).unwrap();
    target["value"] = STANDARD.encode(target_value).into();
    target["args"][2] = STANDARD.encode(target_value.len().to_string()).into();
    target["observed_at"] = "1970-01-01T00:33:20Z".into();
    target["request_started_at"] = target["observed_at"].clone();
    validate_witness(
        &source,
        &serde_json::to_vec(&target).unwrap(),
        Surface::DependencyRequest,
        &[b"session".to_vec()],
        witness_clocks(),
    )
    .unwrap();
    for field in ["cas", "quiet", "noreply", "opcode"] {
        let mut changed = target.clone();
        changed[field] = json!(12);
        assert!(
            validate_witness(
                &source,
                &serde_json::to_vec(&changed).unwrap(),
                Surface::DependencyRequest,
                &[b"session".to_vec()],
                witness_clocks(),
            )
            .is_err()
        );
    }
    target["args"][2] = STANDARD.encode(b"999").into();
    assert!(
        validate_witness(
            &source,
            &serde_json::to_vec(&target).unwrap(),
            Surface::DependencyRequest,
            &[b"session".to_vec()],
            witness_clocks(),
        )
        .is_err()
    );
}

#[test]
fn binary_response_witness_proves_native_get_adaptation_and_keeps_cas_flags_strict() {
    let value = br#"{"expires_at":127}"#;
    let mut frame = vec![0; 24];
    frame[0] = 0x81;
    frame[1] = 0x0c;
    frame[2..4].copy_from_slice(&7u16.to_be_bytes());
    frame[4] = 4;
    frame[8..12].copy_from_slice(&((4 + 7 + value.len()) as u32).to_be_bytes());
    frame[12..16].copy_from_slice(&17u32.to_be_bytes());
    frame[16..24].copy_from_slice(&123u64.to_be_bytes());
    frame.extend(7u32.to_be_bytes());
    frame.extend(b"session");
    frame.extend(value);
    let mut event = source_event(Some(&frame));
    event["wire_protocol"] = "binary".into();
    event["opcode"] = json!(0x0c);
    let source = source_witness(&event, Surface::DependencyResponse).unwrap();
    let mut adapted = vec![frame];
    adapt_binary_get_responses(&mut adapted, 0, 42, Some(b"session"), false).unwrap();
    let slots = crate::memcached::value_slot::extract(&adapted, "binary").unwrap();
    adapted[0] =
        crate::memcached::value_slot::replace(&adapted[0], &slots[0], br#"{"expires_at":1127}"#)
            .unwrap();
    let mut target: serde_json::Value = serde_json::from_slice(&source).unwrap();
    target["response_frames"] = encoded_frames(&adapted);
    target["delivery_request"] = json!({"opcode":0,"opaque":42});
    target["delivery_request_started_at"] = json!(DateTime::from_timestamp(2000, 0).unwrap());
    target["response_delivered_at"] = json!(DateTime::from_timestamp(2005, 0).unwrap());
    validate_witness(
        &source,
        &serde_json::to_vec(&target).unwrap(),
        Surface::DependencyResponse,
        &[b"session".to_vec()],
        witness_clocks(),
    )
    .unwrap();
    for offset in [16, 24, 12, 1] {
        let mut changed = adapted.clone();
        changed[0][offset] ^= 1;
        target["response_frames"] = encoded_frames(&changed);
        assert!(
            validate_witness(
                &source,
                &serde_json::to_vec(&target).unwrap(),
                Surface::DependencyResponse,
                &[b"session".to_vec()],
                witness_clocks(),
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn binary_get_delivery_rebases_json_with_live_correlation_and_finite_consumption() {
    use crate::replay::{MysqlReplayConfig, ReplayRuntime};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (codec, value) in [("json", br#"{"expires_at":1000,"stable":7}"#.to_vec())] {
        let (temp, _policy) = source_fixture_with(false, codec);
        let case = temp.path().join(".traffic-e2e/local/recordings/case");
        let path = temp.path().join("policy.yaml");
        let mut frame = vec![0; 24];
        frame[0] = 0x81;
        frame[1] = 0x0c;
        frame[2..4].copy_from_slice(&7u16.to_be_bytes());
        frame[4] = 4;
        frame[8..12].copy_from_slice(&((11 + value.len()) as u32).to_be_bytes());
        frame[16..24].copy_from_slice(&123u64.to_be_bytes());
        frame.extend(7u32.to_be_bytes());
        frame.extend(b"session");
        frame.extend(&value);
        let mut event = source_event(Some(&frame));
        event["wire_protocol"] = "binary".into();
        event["opcode"] = json!(0x0c);
        std::fs::write(case.join("dependencies.jsonl"), event.to_string()).unwrap();
        crate::replay::write_test_recording_network_manifest(&case);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let report_path = temp.path().join("report.json");
        let runtime = ReplayRuntime::load(
            MysqlReplayConfig {
                case_dir: case.clone(),
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: address,
                fake_cidr: "198.18.0.0/15".into(),
                report_path: Some(report_path.clone()),
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(case.join(".replay/ca.pem")),
                ca_key_path: Some(case.join(".replay/ca-key.pem")),
                policy_path: Some(path),
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            address,
        )
        .await
        .unwrap();
        runtime.write_report().await.unwrap();
        let task = tokio::spawn(async move {
            tokio::select! {_ = runtime.run_tcp(listener)=>{}, _ = runtime.run_report_writer()=>{}}
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let mut request = vec![0; 24];
        request[0] = 0x80;
        request[2..4].copy_from_slice(&7u16.to_be_bytes());
        request[8..12].copy_from_slice(&7u32.to_be_bytes());
        request[12..16].copy_from_slice(&42u32.to_be_bytes());
        request.extend(b"session");
        client.write_all(&request).await.unwrap();
        let mut header = vec![0; 24];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.read_exact(&mut header),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(header[1], 0);
        assert_eq!(&header[2..4], &0u16.to_be_bytes());
        assert_eq!(&header[12..16], &42u32.to_be_bytes());
        assert_eq!(&header[16..24], &123u64.to_be_bytes());
        let mut body = vec![0; u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body[..4], &7u32.to_be_bytes());
        let decoded =
            crate::value_codec::CodecView::decode(&crate::policy::Codec::Json, &body[4..]).unwrap();
        assert!(
            decoded.logical["expires_at"]
                .as_i64()
                .unwrap()
                .abs_diff(Utc::now().timestamp())
                <= 3
        );
        assert_eq!(decoded.logical["stable"], 7);
        client.write_all(&request).await.unwrap();
        assert_eq!(client.read(&mut header).await.unwrap(), 0);
        let mut found = false;
        for _ in 0..150 {
            let report: Value =
                serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
            if report["memcached"]["matched"]
                .as_array()
                .is_some_and(|matched| matched.len() == 1)
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        task.abort();
        assert!(
            found,
            "completed delivery did not publish contract accounting"
        );
    }
}

fn source_event(frame: Option<&[u8]>) -> serde_json::Value {
    let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
    json!({"event_type":"memcached_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
        "timestamp":"1970-01-01T00:16:40Z","duration_ms":0,"target_host":"cache.test","target_port":11211,
        "wire_protocol":"text","command":"get","opcode":null,"key":capture(b"session"),"args":[],
        "value":null,"extras":null,"cas":null,"quiet":frame.is_none(),"noreply":false,
        "response_frames":frame.map(|frame|vec![capture(frame)]).unwrap_or_default(),
        "no_response":frame.is_none(),"outcome":if frame.is_some(){"response"}else{"no_response"},"replay_safe":true})
}

#[test]
fn json_get_delivery_preserves_native_key_flags_cas_and_text_framing() {
    let source = serde_json::to_vec(&json!({"expires_at":1000,"stable":7})).unwrap();
    let plan = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\njson:\n  fields:\n    /expires_at: {kind: time, formats: [unix_seconds]}\n").unwrap().global_json.unwrap();
    let target_at = DateTime::from_timestamp(2000, 0).unwrap();
    let delivery = crate::value_contract::response_delivery::Delivery::prepare_global(
        &source,
        &plan,
        AnchorClocks {
            dependency: ClockPair {
                source: DateTime::from_timestamp(1000, 0),
                target: Some(target_at),
            },
            ..Default::default()
        },
    )
    .unwrap();
    let payload = delivery.render(target_at).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&payload).unwrap(),
        json!({"expires_at":2000,"stable":7})
    );
    let mut frame = format!("VALUE session 17 {} 12345\r\n", source.len()).into_bytes();
    frame.extend(&source);
    frame.extend(b"\r\nEND\r\n");
    let slots =
        crate::memcached::value_slot::extract(std::slice::from_ref(&frame), "text").unwrap();
    let patched = crate::memcached::value_slot::replace(&frame, &slots[0], &payload).unwrap();
    assert!(
        patched.starts_with(format!("VALUE session 17 {} 12345\r\n", payload.len()).as_bytes())
    );
    assert!(patched.ends_with(b"\r\nEND\r\n"));
    let slots =
        crate::memcached::value_slot::extract(std::slice::from_ref(&patched), "text").unwrap();
    assert_eq!(&patched[slots[0].payload.clone()], payload);
}

#[test]
fn payload_evidence_budget_keeps_native_memcached_matching_and_marks_coverage_incomplete() {
    let (temp, mut runtime) = source_fixture_with(true, "");
    let artifacts = temp.path().join(".traffic-e2e/local/runtime/attempt");
    let store = crate::policy_evidence::WitnessStore::new(&artifacts).unwrap();
    runtime
        .request_contracts
        .configure_witnesses(store.clone(), false)
        .unwrap();
    let value = vec![b'x'; 1024 * 1024 + 32];
    let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
    let mut event = source_event(Some(b"STORED\r\n"));
    event["command"] = "set".into();
    event["args"] = json!([
        capture(b"0"),
        capture(b"0"),
        capture(value.len().to_string().as_bytes())
    ]);
    event["value"] = capture(&value);
    let record: RecordedExchange = serde_json::from_value(event).unwrap();
    let mut state = super::super::MemcachedReplayState::default();
    state
        .register_exchange(
            record,
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
        )
        .unwrap();
    let request = MemcachedRequest {
        raw: bytes::Bytes::new(),
        command: "set".into(),
        opcode: None,
        opaque: None,
        key: Some(b"session".to_vec()),
        args: vec![
            b"0".to_vec(),
            b"0".to_vec(),
            value.len().to_string().into_bytes(),
        ],
        value: Some(value),
        extras: None,
        cas: None,
        quiet: false,
        noreply: false,
    };
    assert!(
        state
            .match_memcached(super::super::MemcachedMatchContext {
                active_case_id: Some("case"),
                target: &TargetKey {
                    host: "cache.test".into(),
                    port: 11211
                },
                wire_protocol: MemcachedWireProtocol::Text,
                request: &request,
                policy: Some(&runtime),
                observed_at: DateTime::from_timestamp(2000, 0).unwrap(),
            })
            .is_ok()
    );
    let manifest = store.sealed_manifest().unwrap();
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (1, 0, 1)
    );
    assert!(!manifest.complete);
    assert!(crate::policy_evidence::verify(&artifacts.join("replay.json"), &manifest).is_err());
}
