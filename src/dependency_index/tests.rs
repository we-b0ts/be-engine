fn prepare(
    source: &std::path::Path,
) -> anyhow::Result<(super::model::RunIndex, DependencyIndexReport)> {
    super::store::prepare(source, |_| Ok(()))
}
use super::*;
use std::fs;
use tempfile::TempDir;

fn recording() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("recording-run.json"),
        r#"{"status":"completed","run_id":"run"}"#,
    )
    .unwrap();
    dir
}

fn http(path: &str) -> String {
    serde_json::json!({"event_type":"http_exchange","scheme":"http_gateway","authority":"Example.Test.:80","method":"GET","uri":path,"response_status":200}).to_string() + "\n"
}

fn write_case(root: &std::path::Path, id: &str, raw: &str) -> std::path::PathBuf {
    let file = root.join("apis/api").join(id).join("dependencies.jsonl");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, raw).unwrap();
    file
}

#[test]
fn indexed_lookup_reads_only_candidates_and_preserves_duplicates() {
    let dir = recording();
    let relevant = http("/wanted?a=1");
    let unrelated = serde_json::json!({"event_type":"mysql_exchange","response":{"rows":["x".repeat(1024 * 1024)]}}).to_string();
    let raw = format!("{unrelated}\n{relevant}{relevant}{}", http("/other"));
    let path = write_case(dir.path(), "case", &raw);
    let (index, report) = prepare(dir.path()).unwrap();
    assert_eq!(report.status, "built");
    let file = &index.files[0].index;
    let key = http_key("example.test", 80, "get", "/wanted");
    let candidates: Vec<_> = file
        .http
        .iter()
        .filter(|record| record.key == key)
        .collect();
    assert_eq!(candidates.len(), 2);
    let mut reader = RecordReader::new(4096);
    for candidate in candidates {
        assert_eq!(
            reader
                .read(&path, &file.stamp, &candidate.location)
                .unwrap()
                .as_slice(),
            relevant.as_bytes()
        );
    }
    assert_eq!(reader.source_bytes, relevant.len() as u64 * 2);
    assert!(reader.source_bytes < raw.len() as u64 / 1000);
    assert_eq!(prepare(dir.path()).unwrap().1.status, "reused");
}

#[test]
fn changed_inventory_and_source_invalidate_index() {
    let dir = recording();
    let file = write_case(dir.path(), "one", &http("/one"));
    prepare(dir.path()).unwrap();
    write_case(dir.path(), "two", &http("/two"));
    assert_eq!(prepare(dir.path()).unwrap().1.files, 2);
    fs::write(&file, http("/new")).unwrap();
    let (index, report) = prepare(dir.path()).unwrap();
    assert_eq!(report.status, "built");
    assert!(
        index
            .files
            .iter()
            .any(|file| file.index.http[0].key == http_key("example.test", 80, "GET", "/new"))
    );
    fs::remove_file(file).unwrap();
    assert_eq!(prepare(dir.path()).unwrap().1.files, 1);
}

#[test]
fn reader_checks_integrity_even_for_cached_records() {
    let dir = recording();
    let path = write_case(dir.path(), "one", &http("/one"));
    let index = load_file(&path).unwrap();
    let record = &index.http[0].location;
    let mut reader = RecordReader::new(4096);
    reader.read(&path, &index.stamp, record).unwrap();
    reader.read(&path, &index.stamp, record).unwrap();
    assert_eq!(reader.hits, 1);
    let mut wrong = record.clone();
    wrong.sha256 = "bad".into();
    assert!(reader.read(&path, &index.stamp, &wrong).is_err());
    fs::write(&path, http("/two")).unwrap();
    assert!(reader.read(&path, &index.stamp, record).is_err());
}

#[test]
fn corrupt_index_is_rebuilt_not_used_as_empty_inventory() {
    let dir = recording();
    write_case(dir.path(), "one", &http("/one"));
    let (_, report) = prepare(dir.path()).unwrap();
    fs::write(
        report.index_path,
        r#"{"payload":{"files":[]},"sha256":"wrong"}"#,
    )
    .unwrap();
    let (index, report) = prepare(dir.path()).unwrap();
    assert_eq!(report.status, "built");
    assert_eq!(index.files.len(), 1);
}

#[test]
fn byte_budget_evicts_records_without_affecting_source() {
    let dir = recording();
    let first = http("/one");
    let path = write_case(dir.path(), "one", &(first.clone() + &http("/two")));
    let index = load_file(&path).unwrap();
    let mut reader = RecordReader::new(first.len());
    for position in [0, 1, 0] {
        reader
            .read(&path, &index.stamp, &index.http[position].location)
            .unwrap();
    }
    assert_eq!(reader.hits, 0);
    assert_eq!(fs::read_to_string(path).unwrap(), first + &http("/two"));
}

#[test]
fn incomplete_and_linked_evidence_are_rejected() {
    let dir = recording();
    fs::write(
        dir.path().join("recording-run.json"),
        r#"{"status":"running"}"#,
    )
    .unwrap();
    assert!(prepare(dir.path()).is_err());
    fs::write(
        dir.path().join("recording-run.json"),
        r#"{"status":"completed"}"#,
    )
    .unwrap();
    let source = write_case(dir.path(), "one", &http("/one"));
    let linked = dir.path().join("apis/api/two");
    fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(source, linked.join("dependencies.jsonl")).unwrap();
    assert!(prepare(dir.path()).is_err());
}

#[test]
fn concurrent_builders_publish_one_valid_inventory() {
    let dir = recording();
    write_case(dir.path(), "case", &http("/dep"));
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| prepare(dir.path()).unwrap()))
            .collect();
        for handle in handles {
            let (index, _) = handle.join().unwrap();
            assert_eq!(index.files.len(), 1);
            assert_eq!(index.files[0].index.http.len(), 1);
        }
    });
    assert_eq!(prepare(dir.path()).unwrap().1.status, "reused");
}

#[test]
fn typed_index_envelopes_hash_exact_payloads_and_read_prior_canonical_envelopes() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Fields {
        z: usize,
        a: String,
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("index.json");
    let expected = Fields {
        z: 3,
        a: "source reference".into(),
    };
    super::store::write_json(&path, &expected).unwrap();
    assert_eq!(super::store::read_json::<Fields>(&path).unwrap(), expected);
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["format"], "dependency-index/v2");
    document["payload"]["z"] = 9.into();
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(super::store::read_json::<Fields>(&path).is_err());
    let payload = serde_json::to_value(&expected).unwrap();
    let previous = serde_json::json!({
        "sha256": super::build::digest(&serde_json::to_vec(&payload).unwrap()),
        "payload": payload,
    });
    fs::write(&path, serde_json::to_vec(&previous).unwrap()).unwrap();
    assert_eq!(super::store::read_json::<Fields>(&path).unwrap(), expected);
}

#[tokio::test]
async fn preparation_deadline_cancels_lock_wait_without_publication() {
    use std::os::fd::AsRawFd;
    let dir = recording();
    write_case(dir.path(), "case", &http("/dep"));
    let cache = super::store::cache_directory(dir.path());
    fs::create_dir_all(&cache).unwrap();
    let lock = fs::File::create(cache.join("build.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let error = super::store::prepare_with_timeout(dir.path().into(), 1, |_| Ok(()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("readiness has not started"));
    assert!(!cache.join("manifest.json").exists());
    unsafe {
        libc::flock(lock.as_raw_fd(), libc::LOCK_UN);
    }
    // The cancelled waiter must exit rather than publishing after the deadline.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!cache.join("manifest.json").exists());
    assert_eq!(prepare(dir.path()).unwrap().1.status, "built");
}

#[test]
fn same_size_edit_invalidates_cached_fragment() {
    let dir = recording();
    let file = write_case(dir.path(), "case", &http("/old"));
    let first = load_file(&file).unwrap();
    fs::write(&file, http("/new")).unwrap();
    let second = load_file(&file).unwrap();
    assert_eq!(first.stamp.size, second.stamp.size);
    assert_ne!(first.http[0].key, second.http[0].key);
    assert_ne!(first.sha256, second.sha256);
}

#[test]
fn endpoint_inventory_excludes_non_replayed_mysql_events_and_reserves_motan_ip() {
    let dir = recording();
    let raw = [
        serde_json::json!({"event_type":"mysql_tls_rejected", "target_host":"ignored", "target_port":3306}),
        serde_json::json!({"event_type":"mysql_exchange", "target_host":"ignored", "target_port":3306, "command":"COM_QUIT"}),
        serde_json::json!({"event_type":"motan_exchange", "target_host":"rpc.test", "target_port":8002, "advertised_ip":"198.18.0.8", "request":{"data":"private-frame"}, "response":{"data":"private-response"}}),
    ].into_iter().map(|v| v.to_string()).collect::<Vec<_>>().join("\n");
    let file = write_case(dir.path(), "case", &raw);
    let index = load_file(&file).unwrap();
    assert_eq!(index.endpoints.len(), 1);
    assert_eq!(index.endpoints[0].host, "rpc.test");
    assert_eq!(index.metadata[0].1["target"]["advertised_ip"], "198.18.0.8");
    let persisted = serde_json::to_string(&index).unwrap();
    assert!(!persisted.contains("private-frame"));
    assert!(!persisted.contains("private-response"));
}

#[test]
fn failed_mysql_ping_retains_an_endpoint_while_successful_ping_is_optional() {
    let dir = recording();
    let raw = [
        serde_json::json!({"event_type":"mysql_exchange", "target_host":"healthy.test", "target_port":3306, "command":"COM_PING", "outcome":"response", "response":{"status":"ok"}}),
        serde_json::json!({"event_type":"mysql_exchange", "target_host":"failed.test", "target_port":3306, "command":"COM_PING", "duration_ms":20, "outcome":{"terminated":{"side":"server","kind":"reset","scope":"connection"}}, "response":{"status":"server_terminated"}}),
        serde_json::json!({"event_type":"mysql_exchange", "target_host":"error.test", "target_port":3306, "command":"COM_PING", "outcome":"response", "response":{"status":"error","error_code":2006}}),
    ].into_iter().map(|value| value.to_string()).collect::<Vec<_>>().join("\n");
    let file = write_case(dir.path(), "case", &raw);
    let index = load_file(&file).unwrap();
    assert_eq!(index.endpoints.len(), 2);
    assert!(
        index
            .endpoints
            .iter()
            .any(|endpoint| endpoint.host == "failed.test")
    );
    assert!(
        index
            .endpoints
            .iter()
            .any(|endpoint| endpoint.host == "error.test")
    );
}
