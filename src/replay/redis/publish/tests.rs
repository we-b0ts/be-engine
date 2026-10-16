use super::*;

#[test]
fn publish_uuid_slots_are_bounded_complete_and_preserve_every_other_byte() {
    let source = "0123456789ab4def8123456789abcdef";
    let target = "fedcba98765443218123456789abcdef";
    let payload = format!("\0host_id:{source}\0data:stable");
    let actual = payload.replace(source, target);
    assert_eq!(
        pair(payload.as_bytes(), actual.as_bytes(), &[0])
            .unwrap()
            .len(),
        1
    );
    for bad in [
        actual.replace("stable", "change"),
        actual.replace(target, "00000000000010008000000000000000"),
        actual.replace(target, "00000000000040000000000000000000"),
        actual.replace(target, &format!("a{target}")),
    ] {
        assert!(pair(payload.as_bytes(), bad.as_bytes(), &[0]).is_none());
    }
    assert!(pair(payload.as_bytes(), actual.as_bytes(), &[1]).is_none());
    assert!(spans(&vec![b'a'; MAX_PAYLOAD + 1]).is_none());
    assert!(spans(format!("{source} ").repeat(MAX_UUIDS + 1).as_bytes()).is_none());
    let dashed = Uuid::parse_str(source).unwrap().to_string();
    assert_eq!(spans(dashed.as_bytes()).unwrap().len(), 1);
    assert!(pair(source.as_bytes(), dashed.as_bytes(), &[0]).is_none());
    let stable = "1123456789ab4def8123456789abcdef";
    let source_two = format!("{stable} {source}");
    let target_two = format!("{stable} {target}");
    assert!(pair(source_two.as_bytes(), target_two.as_bytes(), &[1]).is_some());
    assert!(pair(source_two.as_bytes(), target_two.as_bytes(), &[0]).is_none());
    let selector = RedisPublishSelector {
        host: "redis.test".into(),
        port: 6379,
        channel: "events".into(),
        uuid_index: None,
        uuid_field: Some("host_id".into()),
    };
    selector.validate().unwrap();
    assert_eq!(
        selector
            .position(format!("{{\"other\":\"{stable}\",\"host_id\":\"{source}\"}}").as_bytes()),
        Some(1)
    );
    assert_eq!(
        selector.position(format!("{{\"host_id\":\"{source}\"}}").as_bytes()),
        Some(0)
    );
    for bad in [
        format!("{{\"host_id\":null,\"other\":\"{source}\"}}"),
        format!("{{\"old_host_id\":\"{source}\"}}"),
        format!("{{\"host_id\":\"{source}\",\"host_id\":\"{source}\"}}"),
    ] {
        assert_eq!(selector.position(bad.as_bytes()), None);
    }
}

#[test]
fn json_composition_keeps_original_uuid_index_and_binding_scope() {
    use json::JsonContext;
    let source_id = "0123456789ab4def8123456789abcdef";
    let target_id = "fedcba98765443218123456789abcdef";
    let stable_id = "1123456789ab4def8123456789abcdef";
    let source =
        format!(r#"{{"z_host":"{source_id}","a_stable":"{stable_id}","completed_at":1000}}"#);
    let actual =
        format!(r#"{{"z_host":"{target_id}","a_stable":"{stable_id}","completed_at":2000}}"#);
    let mut rules = PublishRules::default();
    rules.configure(vec![PublishRule {
        id: "publisher".into(),
        selector: RedisPublishSelector {
            host: "redis.test".into(),
            port: 6379,
            channel: "events".into(),
            uuid_index: Some(0),
            uuid_field: None,
        },
    }]);
    let source = vec![b"events".to_vec(), source.into_bytes()];
    let actual = vec![b"events".to_vec(), actual.into_bytes()];
    let context = || JsonContext {
        host: "redis.test",
        port: 6379,
        database: 0,
        username: Some("user"),
    };
    let comparison = rules
        .preview_json(context(), &source, &actual)
        .unwrap()
        .unwrap();
    let normalized: serde_json::Value = serde_json::from_slice(&comparison.actual[1]).unwrap();
    assert_eq!(normalized["z_host"], source_id);
    assert_eq!(normalized["a_stable"], stable_id);
    assert_eq!(normalized["completed_at"], 2000);
    // Preview is pure; a conflicting hypothetical comparison has no effect.
    let _ = rules
        .preview_json(context(), &source, &source)
        .unwrap()
        .unwrap();
    assert_eq!(rules.commit_json(comparison), vec!["publisher"]);
    assert!(
        rules
            .preview_json(context(), &source, &source)
            .unwrap()
            .is_err()
    );
    let other = JsonContext {
        host: "redis.test",
        port: 6379,
        database: 1,
        username: Some("user"),
    };
    assert!(rules.preview_json(other, &source, &source).unwrap().is_ok());
}
