use super::*;

#[test]
fn multi_megabyte_json_values_validate_and_render_through_redis_carriers() {
    let runtime = runtime();
    let padding = "x".repeat(2 * 1024 * 1024);
    let source = format!(r#"{{ "padding":"{padding}", "at":1010 }}"#);
    let target = source.replace("\"at\":1010", "\"at\":2010");
    assert!(preview(&runtime, "SET", &["key", &source], &["key", &target]).is_ok());
    let keys = args(&["key"]);
    let raw = bulk(&source);
    let delivery = runtime
        .prepare_redis_delivery(
            "case",
            "case",
            &TargetKey {
                host: "cache.test".into(),
                port: 6379,
            },
            0,
            None,
            "GET",
            &keys,
            &keys,
            &raw,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let rendered = delivery
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    assert_eq!(rendered, bulk(&target));
    let (payload, consumed) = response::bulk_prefix(&rendered).unwrap();
    assert_eq!(payload, target.as_bytes());
    assert_eq!(consumed, rendered.len());
    assert_eq!(
        crate::replay::policy::request_contract::unified_response::redis_bulk_payload(&rendered)
            .unwrap()
            .unwrap(),
        target.as_bytes()
    );
    assert_eq!(
        redis_field_values("GET", &keys, Some(&rendered)).unwrap()[0].payload,
        Some(target.as_bytes())
    );
}

#[test]
fn redis_carriers_reject_frames_above_sixty_four_mib() {
    let oversized = vec![0; crate::value_limits::MAX_VALUE_BYTES + 1];
    let keys = args(&["key"]);
    assert!(response::bulk_prefix(&oversized).is_err());
    assert!(redis_field_values("GET", &keys, Some(&oversized)).is_err());
    assert!(
        crate::replay::policy::request_contract::unified_response::redis_bulk_payload(&oversized)
            .unwrap_err()
            .to_string()
            .contains("64 MiB")
    );
}
