use super::*;

const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";
const Y: &str = "33333333-3333-4333-8333-333333333333";

fn owner() -> RequestContracts {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v2
json:
  fields:
    /item_id: {kind: identity, formats: [uuid]}
    /item/id: {kind: identity, formats: [uuid]}
    /created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap();
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: "/any-api".into(),
            source_uri: String::new(),
            source_input_error: None,
            recorded: DateTime::from_timestamp(1000, 0),
            actual: DateTime::from_timestamp(2000, 0),
            dir: PathBuf::new(),
            conditions: Default::default(),
            source_body: None,
        },
    );
    owner
}

fn payload(path: bool, id: &str) -> Vec<u8> {
    serde_json::to_vec(&if path {
        serde_json::json!({"item":{"id":id},"stable":true})
    } else {
        serde_json::json!({"item_id":id,"stable":true})
    })
    .unwrap()
}

#[test]
fn same_source_identity_connects_json_paths_and_redis_without_resource_declarations() {
    let owner = owner();
    let initial = owner
        .compare_global_value(
            &payload(false, A),
            &payload(false, X),
            &[],
            Default::default(),
        )
        .unwrap();
    owner
        .commit_identity(owner.identity_decision("case", &initial).unwrap())
        .unwrap();
    let target = TargetKey {
        host: "unconfigured-cache.test".into(),
        port: 6380,
    };
    let context = super::super::RedisRequestContext::without_exchange("case", &target, 9, "SET");
    let source = vec![b"unconfigured:key".to_vec(), payload(true, A)];
    let bad = vec![source[0].clone(), payload(true, Y)];
    assert!(
        owner
            .preview_redis_context(&context, &source, &bad)
            .unwrap()
            .is_err()
    );
    let good = vec![source[0].clone(), payload(true, X)];
    owner
        .commit(
            owner
                .preview_redis_context(&context, &source, &good)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let raw = payload(true, A);
    let response = [format!("${}\r\n", raw.len()).as_bytes(), &raw, b"\r\n"].concat();
    let prepared = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &target,
            9,
            None,
            "GET",
            &source[..1],
            &source[..1],
            &response,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let delivered = prepared
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let value = super::super::redis_bulk_payload(&delivered)
        .unwrap()
        .unwrap();
    assert_eq!(crate::json_value::parse(&value).unwrap()["item"]["id"], X);
}

#[test]
fn global_time_delivery_and_optional_fields_preserve_unselected_values() {
    let owner = owner();
    let clocks = owner.contract_clocks(
        Some("case"),
        DateTime::from_timestamp(1000, 0),
        DateTime::from_timestamp(2000, 0),
        None,
        None,
    );
    let source = br#"{ "created_at": 1005, "stable": "unchanged" }"#;
    let delivery = crate::replay::contract_value::Delivery::prepare_global(
        source,
        owner.global_json().unwrap(),
        clocks,
    )
    .unwrap();
    let bytes = delivery
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    let parsed = crate::json_value::parse(&bytes).unwrap();
    assert_eq!(parsed["created_at"], 2005);
    assert_eq!(parsed["stable"], "unchanged");
    let absent = br#"{ "stable": true }"#;
    let delivery = crate::replay::contract_value::Delivery::prepare_global(
        absent,
        owner.global_json().unwrap(),
        Default::default(),
    )
    .unwrap();
    assert_eq!(delivery.render(Utc::now()).unwrap(), absent);
    assert!(delivery.validation().evaluated.is_empty());
    assert!(
        !owner
            .compare_global_value(absent, br#"{"stable":true,"created_at":2000}"#, &[], clocks)
            .unwrap()
            .passed()
    );
    assert!(
        owner
            .compare_global_value(
                br#"{"created_at":null}"#,
                br#"{"created_at":null}"#,
                &[],
                clocks
            )
            .unwrap()
            .passed()
    );
    assert!(
        owner
            .compare_global_value(b"opaque", b"opaque", &[], Default::default())
            .unwrap()
            .passed()
    );
    assert!(
        !owner
            .compare_global_value(b"opaque", b"changed", &[], Default::default())
            .unwrap()
            .passed()
    );
}

#[test]
fn historical_global_json_time_can_be_copied_only_after_the_real_read_is_published() {
    let owner = owner();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let args = vec![b"unconfigured:key".to_vec()];
    let source = br#"{"created_at":1005,"stable":true}"#;
    let raw = [format!("${}\r\n", source.len()).as_bytes(), source, b"\r\n"].concat();
    let mut read = super::super::RedisRequestContext::without_exchange("case", &target, 0, "GET");
    read.recorded_at = DateTime::from_timestamp(1000, 0);
    read.actual_at = DateTime::from_timestamp(2000, 0);
    let pending = owner
        .prepare_redis_time_read(&read, &args, &args, &raw, DateTime::from_timestamp(1001, 0))
        .unwrap()
        .unwrap();
    let delivery = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &target,
            0,
            None,
            "GET",
            &args,
            &args,
            &raw,
            DateTime::from_timestamp(1001, 0),
            read.actual_at,
            read.recorded_at,
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let delivered = delivery
        .render(DateTime::from_timestamp(2001, 0).unwrap())
        .unwrap();
    let mut write = super::super::RedisRequestContext::without_exchange("case", &target, 0, "SET");
    write.recorded_at = DateTime::from_timestamp(1100, 0);
    write.actual_at = DateTime::from_timestamp(2250, 0);
    let before = vec![args[0].clone(), source.to_vec()];
    let after = vec![
        args[0].clone(),
        br#"{"created_at":2005,"stable":true}"#.to_vec(),
    ];
    assert!(
        owner
            .preview_redis_context(&write, &before, &after)
            .unwrap()
            .is_err()
    );
    pending
        .publish(&delivered, DateTime::from_timestamp(2001, 0).unwrap())
        .unwrap();
    assert!(
        owner
            .preview_redis_context(&write, &before, &after)
            .unwrap()
            .is_ok()
    );
    let changed = vec![
        args[0].clone(),
        br#"{"created_at":2006,"stable":true}"#.to_vec(),
    ];
    assert!(
        owner
            .preview_redis_context(&write, &before, &changed)
            .unwrap()
            .is_err()
    );
}

#[test]
fn delivery_pins_equal_unrecognized_identity_scalars_and_keeps_null_mapping_free() {
    for scalar in [
        serde_json::json!(""),
        serde_json::json!("external-id"),
        serde_json::json!(false),
        serde_json::json!(1.5),
    ] {
        let owner = owner();
        let source = serde_json::json!({"item_id":scalar});
        let mut logical = source.clone();
        let (decision, paths) = owner
            .translate_global_identity_logical("case", &source, &mut logical)
            .unwrap();
        assert_eq!(logical, source);
        assert!(paths.is_empty());
        owner.commit_identity(decision).unwrap();
        assert!(owner.has_identities("case"));
    }
    let owner = owner();
    let source = serde_json::json!({"item_id":null});
    let mut logical = source.clone();
    let (decision, _) = owner
        .translate_global_identity_logical("case", &source, &mut logical)
        .unwrap();
    owner.commit_identity(decision).unwrap();
    assert!(!owner.has_identities("case"));
}

#[test]
fn an_unrecognized_identity_delivery_never_rewrites_a_previously_renamed_value() {
    let owner = owner();
    owner
        .commit_identity(
            owner
                .preview_identity_pairs(
                    "case",
                    &[crate::value_contract::identities::IdentityPair {
                        source: serde_json::json!("external-id").to_string(),
                        target: serde_json::json!("changed-id").to_string(),
                    }],
                )
                .unwrap(),
        )
        .unwrap();
    let source = serde_json::json!({"item_id":"external-id"});
    let mut logical = source.clone();
    assert!(
        owner
            .translate_global_identity_logical("case", &source, &mut logical)
            .is_err()
    );
    assert_eq!(logical, source);
}
