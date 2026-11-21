use super::*;
use serde_json::{Value, json};
use uuid::Uuid;

fn record() -> RecordedExchange {
    serde_json::from_value(json!({
        "connection_id": Uuid::nil(), "sequence": 1,
        "target_host": "redis.test", "target_port": 6379,
        "database": 0, "resp_version": 2, "command": "PUBLISH", "args": [],
        "response": {"encoding": "utf8", "data": ":1\r\n"},
        "response_kind": "integer", "replay_safe": true,
    }))
    .unwrap()
}

fn request(host: &str, sid: &str, id: u64) -> Vec<Vec<u8>> {
    vec![
        b"jobs".to_vec(),
        serde_json::to_vec(&json!({
            "method": "emit", "host_id": host, "room": sid, "namespace": "/chat",
            "event": "update", "data": [{"message": "payload"}],
            "callback": [sid, "/chat", id], "binary": false,
        }))
        .unwrap(),
    ]
}

#[test]
fn native_request_identities_keep_forward_and_reverse_correspondences() {
    let record = record();
    let source_host = Uuid::new_v4().simple().to_string();
    let target_host = Uuid::new_v4().simple().to_string();
    let source = request(&source_host, "source", 1);
    let actual = request(&target_host, "target", 2);
    let mut bindings = Correspondences::default();
    let (expected, observed) = bindings
        .compatible_request(&record, &source, &actual)
        .unwrap();
    bindings.bind_request(&record, expected.identity, &observed.identity);
    assert!(
        bindings
            .compatible_request(&record, &source, &actual)
            .is_some()
    );
    assert!(
        bindings
            .compatible_request(&record, &source, &request(&target_host, "different", 2))
            .is_none()
    );
    assert!(
        bindings
            .compatible_request(&record, &request(&source_host, "another", 3), &actual)
            .is_none()
    );
}

#[test]
fn broadcast_session_translation_requires_the_injected_native_receipt() {
    let record = record();
    let broadcast = |host: &str, sid: &str| {
        let mut args = request(host, sid, 1);
        let mut value: Value = serde_json::from_slice(&args[1]).unwrap();
        value["callback"] = Value::Null;
        args[1] = serde_json::to_vec(&value).unwrap();
        args
    };
    let source = broadcast(&Uuid::new_v4().simple().to_string(), "source");
    let actual = broadcast(&Uuid::new_v4().simple().to_string(), "target");
    let bindings = Correspondences::default();
    assert!(
        bindings
            .compatible_broadcast(&record, &source, &actual, |_, _, _| false)
            .is_none()
    );
    assert!(
        bindings
            .compatible_broadcast(&record, &source, &actual, |namespace, before, after| {
                namespace == "/chat" && before == "source" && after == "target"
            })
            .is_some()
    );
}

#[test]
fn rendered_callback_preserves_the_subscription_envelope_and_business_arguments() {
    let source = json!({
        "method": "callback", "host_id": Uuid::new_v4().simple().to_string(),
        "sid": "source", "namespace": "/chat", "id": 1, "args": [{"value": 42}],
    });
    let payload = serde_json::to_vec(&source).unwrap();
    let raw = crate::encode_array(&[b"pmessage", b"jobs*", b"jobs", &payload]);
    let actual = rpc::Identity {
        host: Uuid::new_v4().simple().to_string(),
        sid: "target".into(),
        namespace: "/chat".into(),
        id: 2,
    };
    let rendered = render_callback(&raw, &actual).unwrap();
    let push = crate::parse_pubsub_push(&rendered).unwrap().unwrap();
    assert_eq!(
        push.subscription_kind,
        crate::RedisSubscriptionKind::Pattern
    );
    assert_eq!(push.subject, b"jobs*");
    assert_eq!(push.channel, b"jobs");
    let (identity, value) = rpc::callback(&push.payload).unwrap().unwrap();
    assert_eq!(identity, actual);
    assert_eq!(value["args"], source["args"]);
    assert_eq!(value["namespace"], source["namespace"]);
}
