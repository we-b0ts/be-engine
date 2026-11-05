//! Loader integration for ordinary copies of trusted, sealed recording artifacts.
use super::*;
use crate::dependency_index::{RecordReader, RecordSource};
use serde_json::json;
use std::fs::{self, File, FileTimes};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const RECORDS: usize = 300;
const NOTIFICATIONS: usize = 600;

struct Fixture {
    _temporary: tempfile::TempDir,
    original: PathBuf,
    copied: PathBuf,
    sealed: GlobalIndex,
}

fn capture(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false})
}

fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let recordings = temporary
        .path()
        .join(".traffic-e2e/local/artifacts/recordings");
    let original = recordings.join("original");
    fs::create_dir_all(&original).unwrap();
    let path = original.join("global-dependencies.jsonl");
    let mut output = File::create(&path).unwrap();
    for sequence in 1..=RECORDS {
        writeln!(output,"{}",json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":sequence,
            "target_host":"redis.test","target_port":6379,"database":0,"username":null,"resp_version":2,
            "command":"GET","args":[capture("key")],"response":capture("$3\r\nold\r\n"),"response_kind":"bulk_string","duration_ms":0,"replay_safe":true})).unwrap();
    }
    for ordinal in 0..NOTIFICATIONS {
        writeln!(output,"{}",json!({"event_type":"redis_pub_sub_push","connection_id":uuid::Uuid::nil(),"subscription_sequence":1,
            "target_host":"redis.test","target_port":6379,"database":0,"username":null,
            "response":capture("*3\r\n$7\r\nmessage\r\n$7\r\nupdates\r\n$5\r\nhello\r\n"),
            "duration_ms":ordinal,"replay_safe":true})).unwrap();
    }
    drop(output);
    // Use the ordinary index builder and page publication interfaces to produce
    // the same immutable sibling artifact consumed after recording handoff.
    let (sealed, cache) = load_global_index(&path, crate::replay::validate_index_record).unwrap();
    sealed.records.stage_into(&cache, &original).unwrap();
    for lane in &sealed.notifications {
        lane.pages.stage_into(&cache, &original).unwrap();
    }
    store::write_json(&original.join(GLOBAL_FRAGMENT), &sealed).unwrap();
    let copied = recordings.join("copied");
    copy_tree(&original, &copied);
    Fixture {
        _temporary: temporary,
        original,
        copied,
        sealed,
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
            File::options()
                .write(true)
                .open(&target)
                .unwrap()
                .set_times(
                    FileTimes::new().set_modified(entry.metadata().unwrap().modified().unwrap()),
                )
                .unwrap();
        }
    }
}

fn reject_rescan(_: &Value) -> Result<()> {
    anyhow::bail!("a copied sealed index must not rescan semantic records")
}

#[tokio::test]
async fn recording_process_index_survives_copy_and_missing_pages_fall_back_locally() {
    use crate::recorder::{DependencyConnectFailureEvent, Recorder, RecorderEvent};

    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("periodic-selector".into(), "periodic_task".into());
    let recorder = Recorder::new(temp.path().join("recorder"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    recorder
        .append_global_dependency(
            &RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                client_addr: None,
                protocol: "redis".into(),
                target_host: "cache.test".into(),
                target_port: 6379,
                duration_ms: 0,
                failure_kind: "connection_refused".into(),
                client_outcome: "reset".into(),
            }),
            "background_rule",
            "runtime",
            "periodic-selector",
        )
        .await
        .unwrap();
    recorder.finish_run().await.unwrap();

    let replay = temp.path().join("replay/.traffic-e2e");
    let copied = replay.join("local/artifacts/recordings/copied");
    copy_tree(&recorder.run_dir, &copied);
    let scope = copied.join("indexes/process-scope.json");
    let packaged = copied.join("indexes/process-dependencies");
    let (index, root) = load_global_index(&scope, reject_rescan).unwrap();
    assert_eq!(root, packaged);
    let entries = global_records(&index, &root).unwrap().read_page(0).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].record["event_type"],
        "dependency_connect_failure"
    );

    // A changed scope must not use the copy's portable index even if its
    // physical ledger and manifest are untouched.
    let changed = replay.join("local/artifacts/recordings/changed");
    copy_tree(&recorder.run_dir, &changed);
    let changed_scope = changed.join("indexes/process-scope.json");
    File::options()
        .append(true)
        .open(&changed_scope)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    assert!(load_global_index(&changed_scope, reject_rescan).is_err());

    // A copy without the packaged pages must build in Replay's local cache.
    fs::remove_dir_all(packaged.join(".global-replay-pages")).unwrap();
    let (rebuilt, root) = load_global_index(&scope, crate::replay::validate_index_record).unwrap();
    assert!(root.starts_with(replay.join("local/dependency-index")));
    assert_eq!(rebuilt.sha256, index.sha256);
    let (_, warm) = load_global_index(&scope, reject_rescan).unwrap();
    assert_eq!(warm, root);
    assert!(!packaged.join(".global-replay-pages").exists());

    // A valid index from another scope of this same recording cannot stand in
    // for Process even though both share the physical ledger and manifest.
    copy_tree(
        &recorder.run_dir.join("indexes/startup-dependencies"),
        &packaged,
    );
    assert!(recording::load(&scope, &FileStamp::read(&scope).unwrap()).is_none());
}

#[test]
fn same_inode_same_size_edit_cannot_reuse_a_sealed_hash_after_mtime_is_restored() {
    let fixture = fixture();
    let source = fixture.original.join("global-dependencies.jsonl");
    let previous = FileStamp::read(&source).unwrap();
    let modified = fs::metadata(&source).unwrap().modified().unwrap();
    let bytes = fs::read_to_string(&source).unwrap();
    fs::write(&source, bytes.replacen("old", "new", 1)).unwrap();
    File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_times(FileTimes::new().set_modified(modified))
        .unwrap();
    let current = FileStamp::read(&source).unwrap();
    assert_eq!(previous.inode, current.inode);
    assert_eq!(previous.size, current.size);
    assert_eq!(previous.modified, current.modified);
    assert_ne!(previous.changed, current.changed);
    let (index, _) = load_global_index(&source, |_| Ok(())).unwrap();
    assert_ne!(index.sha256, fixture.sealed.sha256);
}

fn notifications(index: &GlobalIndex, root: &Path) -> Paged<NotificationEntry> {
    assert_eq!(index.notifications.len(), 1);
    Paged::restore(index.notifications[0].pages.clone().resolve(root).unwrap()).unwrap()
}

#[test]
fn copied_sealed_global_reuses_original_pages_with_current_source_identity() {
    let fixture = fixture();
    let original_source = fixture.original.join("global-dependencies.jsonl");
    let copied_source = fixture.copied.join("global-dependencies.jsonl");
    let sealed_bytes = fs::read(fixture.original.join(GLOBAL_FRAGMENT)).unwrap();
    let source_bytes = fs::read(&original_source).unwrap();
    let original_stamp = FileStamp::read(&original_source).unwrap();
    let current_stamp = FileStamp::read(&copied_source).unwrap();
    assert_ne!(original_stamp.inode, current_stamp.inode);
    assert_eq!(original_stamp.size, current_stamp.size);
    assert_eq!(original_stamp.modified, current_stamp.modified);
    let (index, root) = load_global_index(&copied_source, reject_rescan).unwrap();
    assert_eq!(root, fixture.copied);
    assert_eq!(index.stamp, current_stamp);
    assert_eq!(index.sha256, fixture.sealed.sha256);
    let records = global_records(&index, &root).unwrap();
    assert_eq!(records.count, RECORDS);
    assert!(records.pages() > 1);
    let entries = records.read_page(0).unwrap();
    let source = RecordSource::new(
        &copied_source,
        index.stamp.clone(),
        Arc::new(Mutex::new(RecordReader::new(4096))),
    );
    assert_eq!(
        source
            .reference(entries[0].location.clone())
            .load::<Value>()
            .unwrap()["response"],
        capture("$3\r\nold\r\n")
    );
    let pushes = notifications(&index, &root);
    assert_eq!(pushes.count, NOTIFICATIONS);
    assert!(pushes.pages() > 1);
    let last = pushes.read_page(pushes.pages() - 1).unwrap();
    assert_eq!(last.last().unwrap().ordinal, NOTIFICATIONS - 1);
    assert_eq!(last.last().unwrap().duration_ms, (NOTIFICATIONS - 1) as u64);
    let (warm, warm_root) = load_global_index(&copied_source, reject_rescan).unwrap();
    assert_eq!(warm_root, root);
    assert_eq!(warm.stamp, current_stamp);
    assert_eq!(
        fs::read(fixture.original.join(GLOBAL_FRAGMENT)).unwrap(),
        sealed_bytes
    );
    assert_eq!(
        fs::read(fixture.copied.join(GLOBAL_FRAGMENT)).unwrap(),
        sealed_bytes
    );
    assert_eq!(fs::read(&original_source).unwrap(), source_bytes);
    assert_eq!(FileStamp::read(&original_source).unwrap(), original_stamp);
}

#[test]
fn copied_sealed_global_size_or_mtime_changes_use_the_normal_rebuild() {
    static VALIDATIONS: AtomicUsize = AtomicUsize::new(0);
    fn validate(value: &Value) -> Result<()> {
        VALIDATIONS.fetch_add(1, Ordering::Relaxed);
        crate::replay::validate_index_record(value)
    }
    for mutation in ["size", "mtime"] {
        let fixture = fixture();
        let path = fixture.copied.join("global-dependencies.jsonl");
        match mutation {
            "size" => {
                File::options()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"\n")
                    .unwrap();
            }
            "mtime" => {
                let modified = fs::metadata(&path).unwrap().modified().unwrap()
                    + std::time::Duration::from_nanos(1);
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(FileTimes::new().set_modified(modified))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        VALIDATIONS.store(0, Ordering::Relaxed);
        let (index, root) = load_global_index(&path, validate).unwrap();
        assert_ne!(root, fixture.copied, "{mutation}");
        assert!(VALIDATIONS.load(Ordering::Relaxed) > 0, "{mutation}");
        assert_eq!(index.stamp, FileStamp::read(&path).unwrap());
        assert_eq!(global_records(&index, &root).unwrap().count, RECORDS);
        assert_eq!(notifications(&index, &root).count, NOTIFICATIONS);
    }
}

#[test]
fn absent_invalid_or_unsupported_sealed_fragments_fall_back_to_rebuild() {
    for mutation in ["missing", "checksum", "version"] {
        let fixture = fixture();
        let fragment = fixture.copied.join(GLOBAL_FRAGMENT);
        match mutation {
            "missing" => fs::remove_file(&fragment).unwrap(),
            "checksum" => {
                let mut wrapper: Value =
                    serde_json::from_slice(&fs::read(&fragment).unwrap()).unwrap();
                wrapper["sha256"] = json!("invalid");
                fs::write(&fragment, serde_json::to_vec(&wrapper).unwrap()).unwrap();
            }
            "version" => {
                let mut index = fixture.sealed.clone();
                index.version += 1;
                store::write_json(&fragment, &index).unwrap();
            }
            _ => unreachable!(),
        }
        let (index, root) = load_global_index(
            &fixture.copied.join("global-dependencies.jsonl"),
            crate::replay::validate_index_record,
        )
        .unwrap();
        assert_ne!(root, fixture.copied, "{mutation}");
        assert_eq!(global_records(&index, &root).unwrap().count, RECORDS);
        assert_eq!(notifications(&index, &root).count, NOTIFICATIONS);
    }
}

#[test]
fn copied_global_later_pages_still_fail_when_missing_or_corrupt() {
    for kind in ["records", "notifications"] {
        for mutation in ["missing", "corrupt"] {
            let fixture = fixture();
            let (index, root) = load_global_index(
                &fixture.copied.join("global-dependencies.jsonl"),
                reject_rescan,
            )
            .unwrap();
            let manifest = if kind == "records" {
                &index.records
            } else {
                &index.notifications[0].pages
            };
            let directory: PathBuf = serde_json::from_value(
                serde_json::to_value(manifest).unwrap()["directory"].clone(),
            )
            .unwrap();
            let path = root.join(directory).join("1.json");
            match mutation {
                "missing" => fs::remove_file(path).unwrap(),
                "corrupt" => fs::write(path, b"invalid page").unwrap(),
                _ => unreachable!(),
            }
            if kind == "records" {
                let pages = global_records(&index, &root).unwrap();
                assert!(pages.read_page(0).is_ok());
                assert!(pages.read_page(1).is_err(), "{mutation}");
            } else {
                let pages = notifications(&index, &root);
                assert!(pages.read_page(0).is_ok());
                assert!(pages.read_page(1).is_err(), "{mutation}");
            }
        }
    }
}

#[test]
fn copied_global_record_references_reject_source_changes_after_load() {
    let fixture = fixture();
    let path = fixture.copied.join("global-dependencies.jsonl");
    let (index, root) = load_global_index(&path, reject_rescan).unwrap();
    let entry = global_records(&index, &root)
        .unwrap()
        .read_page(0)
        .unwrap()
        .remove(0);
    let source = RecordSource::new(
        &path,
        index.stamp,
        Arc::new(Mutex::new(RecordReader::new(4096))),
    );
    let reference = source.reference(entry.location);
    reference.load::<Value>().unwrap();
    let bytes = fs::read_to_string(&path).unwrap();
    fs::write(&path, bytes.replacen("old", "new", 1)).unwrap();
    assert!(reference.load::<Value>().is_err());
    assert_eq!(
        fs::read_to_string(fixture.original.join("global-dependencies.jsonl")).unwrap(),
        bytes
    );
}
