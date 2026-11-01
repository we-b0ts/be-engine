use super::*;

#[test]
fn memcached_request_start_keeps_explicit_precision_and_legacy_reconstruction() {
    let started = "2026-10-31T01:02:03.123456789Z".parse().unwrap();
    let mut record: RecordedExchange =
        serde_json::from_value(source_event(Some(b"END\r\n"))).unwrap();
    record.request_started_at = Some(started);
    record.duration_ms = u64::MAX;
    assert_eq!(source_start(&record), Some(started));
    record.request_started_at = None;
    assert!(source_start(&record).is_none());
    record.timestamp = DateTime::UNIX_EPOCH;
    record.duration_ms = 0;
    assert!(
        source_start(&record).is_none(),
        "the legacy absent-clock marker is not an observed request"
    );
    record.timestamp = started + chrono::TimeDelta::seconds(30);
    record.duration_ms = 30_000;
    assert_eq!(source_start(&record), Some(started));
}

#[test]
fn memcached_absolute_expiry_matching_and_witnesses_use_request_initiation() {
    let source_at = DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap();
    let target_at = DateTime::from_timestamp(1_800_000_000, 123_456_789).unwrap();
    let capture = |value: &[u8]| json!({"encoding":"base64","data":STANDARD.encode(value)});
    let mut event = source_event(Some(b"STORED\r\n"));
    event["timestamp"] = json!(source_at + chrono::TimeDelta::seconds(30));
    event["request_started_at"] = json!(source_at);
    // Deliberately inconsistent truncated duration: the exact request observation
    // is authoritative and must not be recomputed from response completion.
    event["duration_ms"] = json!(31_000);
    event["command"] = "set".into();
    event["args"] = json!([capture(b"0"), capture(b"1700000060"), capture(b"1")]);
    event["value"] = capture(b"x");
    let record: RecordedExchange = serde_json::from_value(event.clone()).unwrap();
    let mut state = MemcachedReplayState::default();
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
        args: vec![b"0".to_vec(), b"1800000060".to_vec(), b"1".to_vec()],
        value: Some(b"x".to_vec()),
        extras: None,
        cas: None,
        quiet: false,
        noreply: false,
    };
    let target = TargetKey {
        host: "cache.test".into(),
        port: 11211,
    };
    assert!(request_arguments_match(
        None,
        &state.exchanges[0],
        &target,
        MemcachedWireProtocol::Text,
        &request,
        target_at
    ));
    assert_eq!(
        memcached_policy_context(&state.exchanges[0], &target, &request, target_at)
            .recorded_request_started_at,
        Some(source_at)
    );

    let source = source_witness(&event, Surface::DependencyRequest).unwrap();
    let mut actual: Value = serde_json::from_slice(&source).unwrap();
    actual["observed_at"] = json!(target_at);
    actual["request_started_at"] = json!(target_at);
    actual["args"] = json!([
        STANDARD.encode(b"0"),
        STANDARD.encode(b"1800000060"),
        STANDARD.encode(b"1")
    ]);
    let clocks = AnchorClocks::for_request(
        Default::default(),
        ClockPair {
            source: Some(source_at),
            target: Some(target_at),
        },
        Default::default(),
    );
    validate_witness(
        &source,
        &serde_json::to_vec(&actual).unwrap(),
        Surface::DependencyRequest,
        &[b"session".to_vec()],
        clocks,
    )
    .unwrap();

    let mut wrong = request;
    wrong.args[1] = b"1800000030".to_vec();
    assert!(!request_arguments_match(
        None,
        &state.exchanges[0],
        &target,
        MemcachedWireProtocol::Text,
        &wrong,
        target_at
    ));
    actual["args"][1] = json!(STANDARD.encode(b"1800000030"));
    assert!(
        validate_witness(
            &source,
            &serde_json::to_vec(&actual).unwrap(),
            Surface::DependencyRequest,
            &[b"session".to_vec()],
            clocks
        )
        .is_err()
    );
}
