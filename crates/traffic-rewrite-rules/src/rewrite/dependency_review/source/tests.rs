//! Original notification UUIDs remain distinct from their subscription command.
use super::*;
use crate::dependency::observation::fixture_capture;
use crate::dependency_index::{FileStamp, RecordLocation, reconciliation::Catalog};
use serde_json::json;

fn snapshot(
    directory: &Path,
    connection: Uuid,
    subscription: Uuid,
    notifications: &[Uuid],
) -> SourceSnapshot {
    let central_path = directory.join("dependencies.jsonl");
    fs::write(&central_path, b"").unwrap();
    let mut exchanges = BTreeMap::new();
    for (index, id) in std::iter::once(subscription)
        .chain(notifications.iter().copied())
        .enumerate()
    {
        let mut capture = fixture_capture("case");
        capture.exchange_id = id;
        exchanges.insert(
            id,
            SourceExchange {
                capture,
                complete: true,
                selector: json!({"event_type":if id == subscription {
                    "redis_exchange"
                } else {
                    "redis_pub_sub_push"
                }}),
                location: RecordLocation {
                    line: index + 1,
                    offset: 0,
                    length: 0,
                    sha256: digest(b""),
                },
            },
        );
    }
    SourceSnapshot {
        identity: "test-inventory".into(),
        exchanges,
        native: BTreeMap::from([(
            ("redis".into(), connection.to_string(), 4),
            BTreeSet::from([subscription]),
        )]),
        http: BTreeMap::new(),
        apis: BTreeMap::new(),
        inputs: BTreeMap::new(),
        epochs: BTreeSet::new(),
        discovery: Catalog::default(),
        case_defaults: BTreeMap::new(),
        files: BTreeMap::new(),
        central_stamp: FileStamp::read_native(&central_path).unwrap(),
        central_path,
    }
}

#[test]
fn unused_notifications_resolve_independently_of_the_shared_subscription_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let subscription = Uuid::new_v4();
    let notifications: Vec<_> = (0..184).map(|_| Uuid::new_v4()).collect();
    let source = snapshot(directory.path(), connection, subscription, &notifications);
    let mut entries = vec![json!({"case_id":"case","command":"SUBSCRIBE",
        "connection_id":connection,"sequence":4})];
    entries.extend(notifications.iter().enumerate().map(|(index, id)| {
        json!({"case_id":"case","command":"PUBSUB_PUSH","index":index,
            "connection_id":connection,"sequence":4,"source_exchange_id":id})
    }));
    let ids = unused(
        &source,
        &json!({"redis":{"unused_case":entries}}),
        &BTreeSet::from(["case".into()]),
    )
    .unwrap();
    assert_eq!(ids.len(), 185);
    assert_eq!(
        ids,
        std::iter::once(subscription).chain(notifications).collect()
    );
}

#[test]
fn a_notification_never_resolves_to_its_subscription_without_its_own_source_uuid() {
    let directory = tempfile::tempdir().unwrap();
    let connection = Uuid::new_v4();
    let subscription = Uuid::new_v4();
    let notification = Uuid::new_v4();
    let source = snapshot(directory.path(), connection, subscription, &[notification]);
    let mut event = json!({"command":"PUBSUB_PUSH","connection_id":connection,"sequence":4});
    assert!(
        resolve_unused(&source, "redis", &event)
            .unwrap_err()
            .to_string()
            .contains("lacks its own Source exchange identity")
    );
    event["source_exchange_id"] = json!(subscription);
    assert!(
        resolve_unused(&source, "redis", &event)
            .unwrap_err()
            .to_string()
            .contains("does not name an original notification")
    );
    event["source_exchange_id"] = json!(notification);
    assert_eq!(
        resolve_unused(&source, "redis", &event).unwrap(),
        notification
    );
}
