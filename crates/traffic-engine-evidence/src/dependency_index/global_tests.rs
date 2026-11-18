use super::global::*;
use super::*;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn capture(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false})
}

fn redis(response: Value) -> Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
        "target_host":"redis.test","target_port":6379,"database":0,"username":null,
        "resp_version":2,"command":"GET","args":[capture("key")],"response":response,
        "response_kind":"bulk_string","duration_ms":0,"replay_safe":true})
}

fn write(root: &std::path::Path, records: &[Value]) -> std::path::PathBuf {
    let path = root.join("global-dependencies.jsonl");
    std::fs::write(
        &path,
        records.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .unwrap();
    path
}

#[test]
fn global_payload_pages_preserve_all_protocol_evidence_and_mysql_widths() {
    let dir = tempfile::tempdir().unwrap();
    let body = "response-only-value".repeat(1024);
    let records = vec![
        redis(capture(&body)),
        json!({"event_type":"mysql_exchange","command":"COM_QUERY","sql":"SELECT value FROM items",
            "response":{"status":"resultset","columns":[{"name":"value","family":"string","sql_type":"TEXT"}],
                "rows":[[{"kind":"string","value":body}],[{"kind":"string","value":body},{"kind":"string","value":"extra"}]]}}),
        json!({"event_type":"memcached_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "target_host":"memcached.test","target_port":11211,"wire_protocol":"text","command":"get",
            "key":capture("key"),"quiet":false,"noreply":false,"no_response":false,
            "response_frames":[capture(&body)],"replay_safe":true}),
        json!({"event_type":"http_exchange","scheme":"http","authority":"http.test","method":"GET","uri":"/",
            "request_headers":{},"request_body":capture(""),"response_status":200,"response_headers":{},"response_body":capture(&body)}),
        json!({"event_type":"motan_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "target_host":"motan.test","target_port":8002,"advertised_ip":"198.18.0.3","codec_version":1,"command":"service#method",
            "request":capture("request"),"response":capture(&body),"heartbeat":false,"outcome":"response","duration_ms":0,"replay_safe":true}),
        json!({"event_type":"kafka_produce","connection_id":uuid::Uuid::nil(),"request_sequence":1,
            "target_host":"kafka.test","target_port":9092,"topic":"items","key":capture("key"),"value":capture(&body),
            "headers":[{"name":"id","value":capture("header")}],"result":"accepted","outcome":"response","duration_ms":0,"replay_safe":true}),
    ];
    let path = write(dir.path(), &records);
    let (index, root) = load_global_index(
        &path,
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    let inventory = global_records(&index, &root).unwrap();
    assert_eq!(inventory.count, records.len());
    let reader = Arc::new(Mutex::new(RecordReader::new(1)));
    let source = RecordSource::new(&path, index.stamp.clone(), reader.clone());
    let entries = inventory.read_page(0).unwrap();
    assert_eq!(entries[1].native["row_shape"], json!([2, false]));
    for (entry, original) in entries.into_iter().zip(records) {
        assert!(!entry.record.to_string().contains("response-only-value"));
        assert_eq!(
            source.reference(entry.location).load::<Value>().unwrap(),
            original
        );
    }
    // A response larger than the cache budget remains readable without becoming cached.
    assert_eq!(reader.lock().unwrap().hits, 0);
}

#[test]
fn warm_global_index_reuses_pages_and_changed_source_is_never_replayed() {
    static VALIDATIONS: AtomicUsize = AtomicUsize::new(0);
    fn validate(value: &Value) -> anyhow::Result<()> {
        VALIDATIONS.fetch_add(1, Ordering::Relaxed);
        crate::protocols::replay::source::validate_index_record(value)
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), &[redis(capture("$3\r\nold\r\n"))]);
    let (first, root) = load_global_index(&path, validate).unwrap();
    let entry = global_records(&first, &root)
        .unwrap()
        .read_page(0)
        .unwrap()
        .remove(0);
    let source = RecordSource::new(
        &path,
        first.stamp.clone(),
        Arc::new(Mutex::new(RecordReader::new(4096))),
    );
    let reference = source.reference(entry.location);
    reference.load::<Value>().unwrap();
    load_global_index(&path, validate).unwrap();
    assert_eq!(VALIDATIONS.load(Ordering::Relaxed), 1);
    write(dir.path(), &[redis(capture("$3\r\nnew\r\n"))]);
    assert!(reference.load::<Value>().is_err());
    let (second, _) = load_global_index(&path, validate).unwrap();
    assert_ne!(first.sha256, second.sha256);
    assert_eq!(first.stamp.size, second.stamp.size);
    assert_eq!(VALIDATIONS.load(Ordering::Relaxed), 2);
}

#[test]
fn unsafe_and_invalid_payloads_cannot_be_laundered_by_projection() {
    let dir = tempfile::tempdir().unwrap();
    let invalid = json!({"encoding":"base64","data":"not-base64!","truncated":false});
    let mut truncated = capture("partial");
    truncated["truncated"] = true.into();
    let path = write(
        dir.path(),
        &[redis(invalid.clone()), redis(truncated.clone())],
    );
    let (index, root) = load_global_index(
        &path,
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    let entries = global_records(&index, &root).unwrap().read_page(0).unwrap();
    assert_eq!(entries[0].record["response"], invalid);
    assert_eq!(entries[1].record["response"], truncated);
    let path = write(
        dir.path(),
        &[json!({"event_type":"mysql_exchange","command":"COM_QUERY",
        "response":{"status":"resultset","rows":[["invalid typed cell"]]}})],
    );
    assert!(
        load_global_index(
            &path,
            crate::protocols::replay::source::validate_index_record
        )
        .is_err()
    );
}

#[test]
fn global_builds_are_locked_and_cancelled_builds_do_not_publish() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), &[redis(capture("+OK\r\n"))]);
    assert!(
        load_global_index_cancellable(
            &path,
            crate::protocols::replay::source::validate_index_record,
            &AtomicBool::new(true)
        )
        .is_err()
    );
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                scope.spawn(|| {
                    load_global_index(
                        &path,
                        crate::protocols::replay::source::validate_index_record,
                    )
                    .unwrap()
                })
            })
            .collect();
        let mut roots = Vec::new();
        for handle in handles {
            let (index, root) = handle.join().unwrap();
            assert_eq!(index.records.count, 1);
            roots.push(serde_json::to_value(index.records).unwrap());
            assert!(root.join("index.json").is_file());
        }
        assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
    });
}

#[test]
fn paged_details_use_direct_offsets_and_validate_corrupt_pages() {
    let dir = tempfile::tempdir().unwrap();
    let mut writer = PageWriter::new_in(dir.path()).unwrap();
    for i in 0..600 {
        writer.push(i).unwrap();
    }
    let pages = writer.finish().unwrap();
    assert_eq!(pages.page_for(256).unwrap(), 1);
    assert_eq!(pages.page_start(2), 512);
    assert_eq!(pages.read_page(2).unwrap(), (512..600).collect::<Vec<_>>());
    let manifest = pages.manifest();
    let path: std::path::PathBuf =
        serde_json::from_value(serde_json::to_value(&manifest).unwrap()["directory"].clone())
            .unwrap();
    std::fs::write(path.join("1.json"), "corrupted").unwrap();
    assert!(pages.read_page(1).is_err());
    let mut relative = serde_json::to_value(&manifest).unwrap();
    relative["directory"] = "../outside".into();
    assert!(
        serde_json::from_value::<PageManifest>(relative)
            .unwrap()
            .resolve(dir.path())
            .is_err()
    );
}
