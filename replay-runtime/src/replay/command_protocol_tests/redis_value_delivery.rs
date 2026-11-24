use super::*;
use std::sync::Arc;
use traffic_contract::{codec::Codec, rule::FieldContract};
use traffic_policy_value::{MessageSide, RuleBinding, ValueRule};

const ORIGINAL: &str = r#"{"items":[1,2]}"#;
const CHANGED: &str = r#"{ "items": [2, 1] }"#;
const NIL: &[u8] = b"$-1\r\n";
const OK: &[u8] = b"+OK\r\n";

fn bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{value}\r\n", value.len()).into_bytes()
}

fn array(values: &[Option<&str>]) -> Vec<u8> {
    let mut response = format!("*{}\r\n", values.len()).into_bytes();
    for value in values {
        match value {
            Some(value) => response.extend(bulk(value)),
            None => response.extend_from_slice(NIL),
        }
    }
    response
}

fn exchange(connection: Uuid, sequence: u64, args: &[&str], response: &[u8]) -> Value {
    let mut record = redis_dependency(connection, sequence, args[1], response);
    record["command"] = args[0].into();
    record["args"] = args[1..]
        .iter()
        .map(|value| capture_json(value.as_bytes()))
        .collect::<Vec<_>>()
        .into();
    record["response_kind"] = match response[0] {
        b'+' => "simple_string",
        b':' => "integer",
        b'*' => "array",
        b'$' if response == NIL => "null",
        b'$' => "bulk_string",
        _ => unreachable!(),
    }
    .into();
    record
}

fn timed_exchange(
    connection: Uuid,
    sequence: u64,
    args: &[&str],
    response: &[u8],
    timing: std::ops::Range<u64>,
) -> Value {
    let mut record = exchange(connection, sequence, args, response);
    let time = |offset| format!("1970-01-01T00:16:40.{offset:03}Z");
    record["request_started_at"] = time(timing.start).into();
    record["timestamp"] = time(timing.end).into();
    record["duration_ms"] = (timing.end - timing.start).into();
    record
}

async fn send(client: &mut TcpStream, args: &[&str]) {
    let command = args.iter().map(|arg| arg.as_bytes()).collect::<Vec<_>>();
    client
        .write_all(&traffic_protocol_redis::encode_array(&command))
        .await
        .unwrap();
}

async fn request(client: &mut TcpStream, args: &[&str], expected: &[u8]) {
    send(client, args).await;
    let mut reader = traffic_protocol_redis::BufferedReader::new(client, 4096);
    let frame = tokio::time::timeout(
        Duration::from_secs(2),
        traffic_protocol_redis::read_frame(&mut reader),
    )
    .await
    .expect("Redis response timeout")
    .expect("Redis response decode")
    .expect("Redis closed before responding");
    assert_eq!(frame.raw.as_ref(), expected, "Redis {} response", args[0]);
}

async fn assert_closed(client: &mut TcpStream) {
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn start(
    source: &[(&[&str], &[u8])],
) -> (
    tempfile::TempDir,
    PathBuf,
    TcpStream,
    tokio::task::JoinHandle<()>,
) {
    let connection = Uuid::new_v4();
    let records = source
        .iter()
        .enumerate()
        .map(|(index, (args, response))| exchange(connection, index as u64 + 1, args, response))
        .collect::<Vec<_>>();
    start_with_records(&records).await
}

async fn start_with_records(
    records: &[Value],
) -> (
    tempfile::TempDir,
    PathBuf,
    TcpStream,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    std::fs::create_dir(&case).unwrap();
    let records = records
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(case.join("dependencies.jsonl"), records).unwrap();

    let mut providers = crate::protocols::default_providers().as_ref().clone();
    providers
        .bindings_mut()
        .register(
            "redis",
            MessageSide::Request,
            RuleBinding {
                rule: Arc::new(ValueRule {
                    id: "unordered-items".into(),
                    contract: FieldContract::Unordered,
                }),
                selector: serde_json::json!({"kind":"value"}),
                codec: Codec::Json,
                pointer: "/items".into(),
            },
            false,
        )
        .unwrap();
    let report = temp.path().join("report.json");
    let (address, task) = spawn_replay_with_providers(
        &case,
        Some(report.clone()),
        None,
        vec![],
        Arc::new(providers),
    )
    .await;
    let stream = TcpStream::connect(address).await.unwrap();
    (temp, report, stream, task)
}

async fn assert_all_consumed(report: &Path, expected: usize) {
    let report = wait_for_matched_count(report, "redis", expected).await;
    assert_eq!(
        report["dependency_protocols"]["redis"]["unused_case"],
        serde_json::json!([])
    );
    assert_eq!(
        report["dependency_protocols"]["redis"]["unmatched"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn redis_reads_the_exact_target_string_and_clears_it_after_later_writes() {
    let original = bulk(ORIGINAL);
    let changed = bulk(CHANGED);
    let recorded_mget = array(&[Some(ORIGINAL), None, Some(ORIGINAL)]);
    let source: &[(&[&str], &[u8])] = &[
        (&["SET", "key", ORIGINAL], OK),
        (&["GET", "key"], &original),
        (&["MSET", "key", ORIGINAL, "other", ORIGINAL], OK),
        (&["MGET", "key", "missing", "other"], &recorded_mget),
        (&["SET", "key", ORIGINAL], OK),
        (&["GET", "key"], &original),
        (&["SET", "key", ORIGINAL], OK),
        (&["SETEX", "key", "30", ORIGINAL], OK),
        (&["GET", "key"], &original),
        (&["DEL", "key"], b":1\r\n"),
        (&["GET", "key"], NIL),
    ];
    let (_temp, report, mut client, task) = start(source).await;

    request(&mut client, &["SET", "key", CHANGED], OK).await;
    request(&mut client, &["GET", "key"], &changed).await;
    request(
        &mut client,
        &["MSET", "key", CHANGED, "other", ORIGINAL],
        OK,
    )
    .await;
    let target_mget = array(&[Some(CHANGED), None, Some(ORIGINAL)]);
    request(
        &mut client,
        &["MGET", "key", "missing", "other"],
        &target_mget,
    )
    .await;
    request(&mut client, &["SET", "key", ORIGINAL], OK).await;
    request(&mut client, &["GET", "key"], &original).await;
    request(&mut client, &["SET", "key", CHANGED], OK).await;
    request(&mut client, &["SETEX", "key", "30", ORIGINAL], OK).await;
    request(&mut client, &["GET", "key"], &original).await;
    request(&mut client, &["DEL", "key"], b":1\r\n").await;
    request(&mut client, &["GET", "key"], NIL).await;
    assert_all_consumed(&report, source.len()).await;

    send(&mut client, &["GET", "key"]).await;
    assert_closed(&mut client).await;
    wait_for_unmatched_count(&report, "redis", 1).await;
    task.abort();
}

#[tokio::test]
async fn finite_redis_eval_time_keeps_the_unbound_limit_strict() {
    use sha2::{Digest, Sha256};
    use traffic_model::{
        attribution::DependencyOwner,
        recording::{CaptureMetadata, CapturePhase, ProtocolRef},
    };

    const SCRIPT: &str = "return {}";
    const KEY: &str = "pending";
    const EMPTY: &[u8] = b"*0\r\n";
    let temp = tempfile::tempdir().unwrap();
    let case_id = Uuid::new_v4();
    let case = temp.path().join(case_id.to_string());
    std::fs::create_dir(&case).unwrap();
    std::fs::write(case.join("request.json"), r#"{"method":"GET","uri":"/"}"#).unwrap();
    std::fs::write(case.join("expected-response.json"), "{}").unwrap();
    let connection = Uuid::new_v4();
    let process_epoch = Uuid::new_v4();
    let started_at = chrono::DateTime::from_timestamp(1_795_450_259, 483_459_500).unwrap();
    let records = (1..=2)
        .map(|sequence| {
            let mut record = exchange(
                connection,
                sequence,
                &[
                    "EVAL",
                    SCRIPT,
                    "1",
                    KEY,
                    "1795450259.4834595",
                    "1795450264.4834595",
                    "4",
                ],
                EMPTY,
            );
            let recorded_time = serde_json::to_value(started_at).unwrap();
            record["request_started_at"] = recorded_time.clone();
            record["timestamp"] = recorded_time;
            record["capture"] = serde_json::to_value(CaptureMetadata {
                transformations: Vec::new(),
                exchange_id: Uuid::new_v4(),
                sequence,
                process_epoch,
                phase: CapturePhase::Runtime,
                observed_case: Some(case_id),
                admitted_case: Some(case_id),
                started_at,
                protocol_ref: ProtocolRef::connection("redis", connection, sequence),
                attribution: DependencyOwner::Case {
                    origin_case_id: case_id,
                    task_instance: None,
                },
                matched_rule_id: None,
                matched_rule_ids: Vec::new(),
                effect_index: 0,
                semantic_required: true,
            })
            .unwrap();
            record.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(case.join("dependencies.jsonl"), records).unwrap();
    let policy_path = temp.path().join("policy.yaml");
    let digest = format!("{:x}", Sha256::digest(SCRIPT));
    std::fs::write(&policy_path, format!(
        "format: traffic-policy/v3\nredis:\n  keys:\n    {KEY}:\n      commands:\n        - operation: EVAL\n          script: {{sha256: {digest}}}\n          arguments:\n            3: {{kind: time, formats: [unix_seconds]}}\n            4: {{kind: time, formats: [unix_seconds]}}\n"
    )).unwrap();
    let report = temp.path().join("report.json");
    let (address, task) =
        spawn_replay_configured(&case, Some(report.clone()), Some(policy_path), vec![]).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    let now = chrono::Utc::now().timestamp_micros() as f64 / 1_000_000.0;
    let now_string = format!("{now:.6}");
    let deadline = format!("{:.6}", now + 5.0);
    request(
        &mut client,
        &["EVAL", SCRIPT, "1", KEY, &now_string, &deadline, "4"],
        EMPTY,
    )
    .await;

    send(
        &mut client,
        &["EVAL", SCRIPT, "1", KEY, &now_string, &deadline, "5"],
    )
    .await;
    assert_closed(&mut client).await;
    let failed = wait_for_unmatched_count(&report, "redis", 1).await;
    assert_eq!(failed["dependency_protocols"]["redis"]["matched_count"], 1);
    assert_eq!(
        failed["dependency_protocols"]["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    task.abort();
}

#[tokio::test]
async fn redis_reads_target_values_on_a_second_connection_with_source_causality() {
    let source_writer = Uuid::new_v4();
    let source_reader = Uuid::new_v4();
    let original = bulk(ORIGINAL);
    let records = [
        timed_exchange(source_writer, 1, &["SET", "proven", ORIGINAL], OK, 0..10),
        timed_exchange(source_reader, 1, &["GET", "proven"], &original, 20..21),
        timed_exchange(source_writer, 2, &["SET", "overlap", ORIGINAL], OK, 30..40),
        timed_exchange(source_reader, 2, &["GET", "overlap"], &original, 35..50),
    ];
    let (_temp, report, mut writer, task) = start_with_records(&records).await;
    let mut reader = TcpStream::connect(writer.peer_addr().unwrap())
        .await
        .unwrap();

    request(&mut writer, &["SET", "proven", CHANGED], OK).await;
    request(&mut reader, &["GET", "proven"], &bulk(CHANGED)).await;
    request(&mut writer, &["SET", "overlap", CHANGED], OK).await;
    request(&mut reader, &["GET", "overlap"], &bulk(ORIGINAL)).await;
    assert_all_consumed(&report, records.len()).await;
    task.abort();
}

#[tokio::test]
async fn redis_readback_uses_a_proven_set_between_independent_overlaps() {
    let left = Uuid::new_v4();
    let right = Uuid::new_v4();
    let records = [
        timed_exchange(left, 1, &["GET", "key"], NIL, 0..10),
        timed_exchange(right, 1, &["GET", "key"], NIL, 5..15),
        timed_exchange(left, 2, &["SET", "key", ORIGINAL], OK, 20..21),
        timed_exchange(right, 2, &["GET", "key"], &bulk(ORIGINAL), 23..24),
        timed_exchange(left, 3, &["SET", "key", ORIGINAL], OK, 30..40),
        timed_exchange(right, 3, &["SET", "key", ORIGINAL], OK, 35..45),
    ];
    let (_temp, report, mut writer, task) = start_with_records(&records).await;
    let mut reader = TcpStream::connect(writer.peer_addr().unwrap())
        .await
        .unwrap();

    request(&mut writer, &["GET", "key"], NIL).await;
    request(&mut reader, &["GET", "key"], NIL).await;
    request(&mut writer, &["SET", "key", CHANGED], OK).await;
    request(&mut reader, &["GET", "key"], &bulk(CHANGED)).await;
    request(&mut writer, &["SET", "key", ORIGINAL], OK).await;
    request(&mut reader, &["SET", "key", ORIGINAL], OK).await;
    assert_all_consumed(&report, records.len()).await;
    task.abort();
}

#[tokio::test]
async fn redis_rejects_a_read_overtaken_by_a_later_target_write_on_another_connection() {
    let source_writer = Uuid::new_v4();
    let records = [
        timed_exchange(source_writer, 1, &["SET", "key", ORIGINAL], OK, 0..10),
        timed_exchange(Uuid::new_v4(), 1, &["GET", "key"], &bulk(ORIGINAL), 20..21),
        timed_exchange(source_writer, 2, &["SET", "key", ORIGINAL], OK, 30..40),
    ];
    let (_temp, report, mut writer, task) = start_with_records(&records).await;
    let mut reader = TcpStream::connect(writer.peer_addr().unwrap())
        .await
        .unwrap();

    request(&mut writer, &["SET", "key", CHANGED], OK).await;
    request(&mut writer, &["SET", "key", ORIGINAL], OK).await;
    wait_for_matched_count(&report, "redis", 2).await;
    send(&mut reader, &["GET", "key"]).await;
    assert_closed(&mut reader).await;
    let report = wait_for_unmatched_count(&report, "redis", 1).await;
    let redis = &report["dependency_protocols"]["redis"];
    assert_eq!(redis["matched_count"], 2);
    assert_eq!(redis["unused_case"].as_array().unwrap().len(), 1);
    assert!(
        redis["unmatched"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("current Target write")
    );
    task.abort();
}

#[tokio::test]
async fn redis_reads_target_hash_fields_and_keeps_nil_and_empty_values_distinct() {
    let original = bulk(ORIGINAL);
    let changed = bulk(CHANGED);
    let recorded_hmget = array(&[Some(ORIGINAL), None, Some(""), Some(ORIGINAL)]);
    let recorded_hgetall = array(&[
        Some("keep"),
        Some(ORIGINAL),
        Some("empty"),
        Some(""),
        Some("update"),
        Some(ORIGINAL),
    ]);
    let recorded_after_delete = array(&[None, Some(ORIGINAL)]);
    let source: &[(&[&str], &[u8])] = &[
        (
            &["HSET", "hash", "update", ORIGINAL, "keep", ORIGINAL],
            b":2\r\n",
        ),
        (&["HSET", "hash", "update", ORIGINAL], b":0\r\n"),
        (&["HGET", "hash", "update"], &original),
        (
            &["HMGET", "hash", "update", "missing", "empty", "keep"],
            &recorded_hmget,
        ),
        (&["HGETALL", "hash"], &recorded_hgetall),
        (&["HDEL", "hash", "update"], b":1\r\n"),
        (&["HMGET", "hash", "update", "keep"], &recorded_after_delete),
        (&["HGETALL", "missing"], b"*0\r\n"),
    ];
    let (_temp, report, mut client, task) = start(source).await;

    request(
        &mut client,
        &["HSET", "hash", "update", ORIGINAL, "keep", CHANGED],
        b":2\r\n",
    )
    .await;
    request(&mut client, &["HSET", "hash", "update", CHANGED], b":0\r\n").await;
    request(&mut client, &["HGET", "hash", "update"], &changed).await;
    let target_hmget = array(&[Some(CHANGED), None, Some(""), Some(CHANGED)]);
    request(
        &mut client,
        &["HMGET", "hash", "update", "missing", "empty", "keep"],
        &target_hmget,
    )
    .await;
    let target_hgetall = array(&[
        Some("keep"),
        Some(CHANGED),
        Some("empty"),
        Some(""),
        Some("update"),
        Some(CHANGED),
    ]);
    request(&mut client, &["HGETALL", "hash"], &target_hgetall).await;
    request(&mut client, &["HDEL", "hash", "update"], b":1\r\n").await;
    let target_after_delete = array(&[None, Some(CHANGED)]);
    request(
        &mut client,
        &["HMGET", "hash", "update", "keep"],
        &target_after_delete,
    )
    .await;
    request(&mut client, &["HGETALL", "missing"], b"*0\r\n").await;
    assert_all_consumed(&report, source.len()).await;
    task.abort();
}
