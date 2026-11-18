use super::*;
use crate::protocols::recording::events::{DependencyConnectFailureEvent, RecorderEvent};
use crate::recorder::{CaseContext, Recorder};
use uuid::Uuid;

fn copy(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let path = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy(&entry.path(), &path);
        } else {
            fs::copy(entry.path(), path).unwrap();
        }
    }
}

#[tokio::test]
async fn published_case_index_survives_later_appends_and_copy_without_a_rebuild() {
    let temporary = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temporary.path().join("recorder"))
        .await
        .unwrap();
    let mut first = None;
    for port in [6379, 6380] {
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "socket".into(),
            uri_group: Some("socket.io".into()),
        };
        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
                    id: Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    client_addr: None,
                    protocol: "redis".into(),
                    target_host: "cache.test".into(),
                    target_port: port,
                    duration_ms: 0,
                    failure_kind: "connection_refused".into(),
                    client_outcome: "reset".into(),
                }),
                "fixture_request_admission",
            )
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();
        first.get_or_insert(case);
    }
    let first = recorder.case_dir(&first.unwrap());
    let published: FileIndex = store::read_json(&first.join(FRAGMENT)).unwrap();
    recorder.finish_run().await.unwrap();
    let original = recorder.run_dir.as_ref();
    let ledger =
        FileStamp::read_native(&original.join(traffic_model::compact::DEPENDENCIES)).unwrap();
    assert!(published.stamp.size < ledger.size);
    let copied = temporary
        .path()
        .join("target/.traffic-e2e/recordings/copied");
    copy(original, &copied);
    let view = copied
        .join(first.strip_prefix(original).unwrap())
        .join(scoped::CASE_SCOPE);
    let source = scoped::resolve(&view).unwrap();
    let cache = store::file_cache_directory(&view, &source).unwrap();
    let index = store::load_file(&view).unwrap();
    assert_eq!(index.events, 1);
    assert_eq!(index.sha256, published.sha256);
    assert_eq!(index.stamp, FileStamp::read_native(&source.path).unwrap());
    assert!(
        !cache.exists(),
        "a copied recording uses its packaged index"
    );

    // A bad or absent optional fragment rebuilds in private Replay storage.
    fs::write(view.with_file_name(FRAGMENT), b"invalid index").unwrap();
    let fallback = store::load_file(&view).unwrap();
    assert_eq!(fallback.sha256, index.sha256);
    assert!(cache.join("file.json").is_file());
}
