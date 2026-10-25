use super::*;
use crate::dependency_index::global::{GlobalEntry, global_records, load_global_index};
use serde_json::json;

mod ownership;

fn expected_phase(record: &DependencyRecord) -> Option<Phase> {
    // Exhaustive: adding a dependency variant must also decide its load phase.
    match record {
        DependencyRecord::MysqlConnection(_)
        | DependencyRecord::MysqlExchange(_)
        | DependencyRecord::RedisPubSubPush(_)
        | DependencyRecord::RedisConnection(_)
        | DependencyRecord::MemcachedConnection(_)
        | DependencyRecord::KafkaConnection(_)
        | DependencyRecord::MotanConnection(_)
        | DependencyRecord::ProxyError(_) => Some(Phase::Metadata),
        DependencyRecord::TcpGatewayConnection(_)
        | DependencyRecord::HttpExchange(_)
        | DependencyRecord::RedisExchange(_)
        | DependencyRecord::MemcachedExchange(_)
        | DependencyRecord::MotanExchange(_)
        | DependencyRecord::KafkaProduce(_)
        | DependencyRecord::KafkaFetch(_)
        | DependencyRecord::KafkaDelivery(_) => Some(Phase::Exchanges),
        DependencyRecord::Other => None,
    }
}

fn capture(value: &str) -> Value {
    json!({"encoding":"utf8","data":value,"truncated":false})
}

fn records() -> Vec<Value> {
    let id = Uuid::nil();
    vec![
        json!({"event_type":"redis_exchange","connection_id":id,"sequence":1,
            "target_host":"redis.test","target_port":6379,"database":0,"resp_version":2,
            "command":"GET","args":[capture("key")],"response":capture("$5\r\nvalue\r\n"),
            "response_kind":"bulk_string","replay_safe":true}),
        json!({"event_type":"mysql_connection","id":id}),
        json!({"event_type":"redis_connection","target_host":"redis.test","target_port":6379,"replay_safe":true}),
        json!({"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SELECT 1",
            "response":{"status":"resultset","columns":[{"name":"n","family":"number","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":1}]]}}),
        json!({"event_type":"http_exchange","scheme":"http","authority":"http.test:80","method":"GET","uri":"/",
            "request_headers":{},"request_body":capture(""),"response_status":200,"response_body":capture("body")}),
        json!({"event_type":"memcached_connection","target_host":"memcached.test","target_port":11211,"replay_safe":true}),
        json!({"event_type":"memcached_exchange","connection_id":id,"sequence":1,"target_host":"memcached.test",
            "target_port":11211,"wire_protocol":"text","command":"get","key":capture("key"),
            "quiet":false,"noreply":false,"no_response":false,"response_frames":[capture("END\r\n")],"replay_safe":true}),
        json!({"event_type":"kafka_connection","target_host":"kafka.test","target_port":9092,"replay_safe":true}),
        json!({"event_type":"kafka_produce","connection_id":id,"request_sequence":1,"target_host":"kafka.test",
            "target_port":9092,"topic":"topic","value":capture("payload"),"result":"accepted","outcome":"response","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"kafka_fetch","connection_id":id,"sequence":1,"target_host":"kafka.test","target_port":9092,
            "topics":["topic"],"outcome":"response","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"kafka_delivery","connection_id":id,"fetch_sequence":1,"target_host":"kafka.test","target_port":9092,
            "topic":"topic","value":capture("payload"),"message_timestamp_ms":0,"replay_safe":true}),
        json!({"event_type":"motan_connection","target_host":"motan.test","target_port":8002,"advertised_ip":"198.18.0.3","replay_safe":true}),
        json!({"event_type":"motan_exchange","connection_id":id,"sequence":1,"target_host":"motan.test","target_port":8002,
            "advertised_ip":"198.18.0.3","codec_version":1,"command":"service#method","request":capture("request"),
            "response":capture("response"),"heartbeat":false,"outcome":"response","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"redis_pub_sub_push","connection_id":id,"subscription_sequence":1,
            "rpc_request":{"connection_id":id,"sequence":1},"target_host":"redis.test","target_port":6379,
            "database":0,"response":capture("retained-original-frame"),"duration_ms":0,"replay_safe":true}),
        json!({"event_type":"tcp_gateway_connection","fake_addr":"198.18.0.4:8080","client_to_server_bytes":0,"server_to_client_bytes":0}),
        json!({"event_type":"proxy_error","protocol":"redis","error":"recorded transport failure"}),
        json!({"event_type":"future_event","ignored":"same Other semantics"}),
    ]
}

fn indexed(records: &[Value]) -> (tempfile::TempDir, Paged<GlobalEntry>, Arc<RecordSource>) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".traffic-e2e/recordings/run");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("global-dependencies.jsonl");
    std::fs::write(
        &path,
        records
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let (index, cache) = load_global_index(&path, validate_index_record).unwrap();
    let pages = global_records(&index, &cache).unwrap();
    let source = RecordSource::new(
        &path,
        index.stamp,
        Arc::new(std::sync::Mutex::new(RecordReader::new(1024))),
    );
    (root, pages, source)
}

#[tokio::test]
async fn both_phases_cover_every_protocol_in_source_order_with_bounded_page_batches() {
    let originals = (0..40).flat_map(|_| records()).collect::<Vec<_>>();
    let (_root, pages, source) = indexed(&originals);
    for phase in [Phase::Metadata, Phase::Exchanges] {
        let expected = originals
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                let record: DependencyRecord = serde_json::from_value(value.clone()).unwrap();
                (std::mem::discriminant(&expected_phase(&record)?)
                    == std::mem::discriminant(&phase))
                .then_some(index + 1)
            })
            .collect::<Vec<_>>();
        let (mut receiver, task) = stream(pages.clone(), source.clone(), phase);
        let mut observed = Vec::new();
        let mut batches = 0;
        let mut combined = false;
        while let Some(batch) = receiver.recv().await {
            assert!(batch.len() <= 256);
            combined |= batch.len() > 1;
            batches += 1;
            for (record, reference, shape) in batch {
                assert_eq!(
                    std::mem::discriminant(&expected_phase(&record).unwrap()),
                    std::mem::discriminant(&phase)
                );
                let original = reference.load::<Value>().unwrap();
                assert_eq!(original, originals[reference.location.line - 1]);
                if matches!(record, DependencyRecord::MysqlExchange(_)) {
                    assert_eq!(shape, Some((1, true)));
                }
                observed.push(reference.location.line);
            }
        }
        task.await.unwrap().unwrap();
        assert!(combined && batches <= pages.pages());
        assert_eq!(observed, expected);
    }
}

#[tokio::test]
async fn source_changes_fail_even_when_a_phase_selects_no_records() {
    let (_root, pages, source) = indexed(&records()[..1]);
    std::fs::write(source.path(), "changed\n").unwrap();
    let (receiver, task) = stream(pages, source, Phase::Metadata);
    assert!(
        consume(receiver, task, "phase failed", |_| Ok(()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn registration_failure_closes_and_joins_the_bounded_producer() {
    let originals = (0..40).flat_map(|_| records()).collect::<Vec<_>>();
    let (_root, pages, source) = indexed(&originals);
    let (receiver, task) = stream(pages, source, Phase::Exchanges);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        consume(receiver, task, "phase failed", |_| {
            anyhow::bail!("registration rejected")
        }),
    )
    .await
    .unwrap();
    assert!(format!("{:#}", result.unwrap_err()).contains("registration rejected"));
}

#[tokio::test]
async fn a_corrupt_page_is_not_silently_filtered_out() {
    let (_root, pages, source) = indexed(&records()[..1]);
    let manifest = serde_json::to_value(pages.manifest()).unwrap();
    let path = std::path::Path::new(manifest["directory"].as_str().unwrap()).join("0.json");
    std::fs::write(path, "corrupt").unwrap();
    let (receiver, task) = stream(pages, source, Phase::Metadata);
    assert!(
        consume(receiver, task, "phase failed", |_| Ok(()))
            .await
            .is_err()
    );
}
