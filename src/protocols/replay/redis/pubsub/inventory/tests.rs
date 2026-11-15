use super::*;
use crate::dependency_index::{FileStamp, PageManifest, RecordReader};
use serde_json::json;

fn inventory(
    count: usize,
) -> (
    tempfile::TempDir,
    Vec<crate::dependency_index::global::NotificationLane>,
    Arc<RecordSource>,
) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("global-dependencies.jsonl");
    std::fs::write(&source, "").unwrap();
    std::fs::create_dir(root.path().join("pages")).unwrap();
    let lengths: Vec<_> = (0..count)
        .step_by(256)
        .map(|start| (count - start).min(256))
        .collect();
    let pages: PageManifest =
        serde_json::from_value(json!({"directory":"pages","count":count,"lengths":lengths}))
            .unwrap();
    let record = json!({"target_host":"redis.test","target_port":6379,"database":0,"username":null,
        "connection_id":Uuid::nil(),"subscription_sequence":1,"rpc_request":null,"duration_ms":0,
        "response":{"encoding":"base64","data":"","truncated":false},"replay_safe":true});
    let lanes = vec![crate::dependency_index::global::NotificationLane {
        record,
        kind: 0,
        subject: b"jobs".to_vec(),
        pages,
    }];
    let source = RecordSource::new(
        &source,
        FileStamp::read(&source).unwrap(),
        Arc::new(std::sync::Mutex::new(RecordReader::new(1024))),
    );
    (root, lanes, source)
}

#[test]
fn untouched_million_notification_inventory_has_no_per_record_session_allocation_or_reads() {
    let (root, lanes, source) = inventory(1_000_001);
    let mut indexed = IndexedNotifications::default();
    // There are intentionally no page files: restoring immutable metadata and
    // the default Available state must never materialize a million entries.
    indexed
        .restore(
            lanes.clone(),
            root.path(),
            source.clone(),
            ReplaySource::Startup,
        )
        .unwrap();
    assert_eq!(indexed.total, 1_000_001);
    assert!(indexed.lanes[0].statuses.is_empty());
    assert!(indexed.available(0, 1_000_000));
    indexed.responding(0, 1_000_000);
    assert!(!indexed.available(0, 1_000_000));
    indexed.fail(0, 1_000_000);
    indexed.fail(0, 1_000_000);
    assert_eq!(indexed.failed, 1);
    indexed.complete(0, 1_000_000);
    indexed.complete(0, 1_000_000);
    indexed.fail(0, 1_000_000);
    indexed.responding(0, 0);
    indexed.fail(0, 1);
    assert_eq!(indexed.delivered, 1);
    assert_eq!(indexed.failed, 1);
    assert_eq!(indexed.lanes[0].statuses.len(), 3);
    indexed.seal().unwrap();
    let mut fresh = IndexedNotifications::default();
    fresh
        .restore(lanes, root.path(), source, ReplaySource::Startup)
        .unwrap();
    assert!(fresh.available(0, 1_000_000));
    assert!(fresh.lanes[0].statuses.is_empty());
    assert_eq!((fresh.delivered, fresh.failed), (0, 0));
}
