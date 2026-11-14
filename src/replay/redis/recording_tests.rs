use super::*;
use serde_json::json;

#[test]
fn native_capture_keeps_flat_witness_fields_and_excludes_runtime_authorization() {
    let mut record: RecordedExchange = serde_json::from_value(json!({
        "event_type": "redis_exchange",
        "id": Uuid::nil(),
        "connection_id": Uuid::nil(),
        "sequence": 3,
        "target_host": "cache.test",
        "target_port": 6379,
        "resp_version": 2,
        "database": 1,
        "username": null,
        "command": "GET",
        "args": [{"encoding":"utf8", "data":"key"}],
        "response_kind": "bulk_string",
        "response": {"encoding":"utf8", "data":"$1\r\nv\r\n"},
        "replay_safe": true,
        "lifecycle_cleanup": true
    }))
    .unwrap();
    assert_eq!(record.native.id, Some(Uuid::nil()));
    assert!(!record.lifecycle_cleanup);
    assert_eq!(record.native.args[0].decode().unwrap(), b"key");
    let expected = json!({
        "timestamp": null,
        "connection_id": Uuid::nil(),
        "sequence": 3,
        "target_host": "cache.test",
        "target_port": 6379,
        "resp_version": 2,
        "database": 1,
        "username": null,
        "command": "GET",
        "args": [{"encoding":"utf8", "data":"key", "truncated":false}],
        "response_kind": "bulk_string",
        "response": {"encoding":"utf8", "data":"$1\r\nv\r\n", "truncated":false},
        "outcome": "response",
        "duration_ms": 0,
        "replay_safe": true,
        "cache_snapshot_rule": null,
        "cache_snapshot_hit": false,
        "session_setup": false,
        "capture": null
    });
    assert_eq!(serde_json::to_value(&record).unwrap(), expected);
    let before = serde_json::to_vec(&record).unwrap();
    record.lifecycle_cleanup = true;
    assert_eq!(serde_json::to_vec(&record).unwrap(), before);
}
