use super::*;

fn scalar_runtime() -> RequestContracts {
    let policy = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /id: {kind: identity, formats: [{prefix: text-, format: decimal}]}
    /at: {kind: time, formats: [unix_seconds]}
redis:
  keys:
    'clock:*': {kind: time, formats: [unix_seconds]}
    'text:*': {kind: identity, formats: [{prefix: text-, format: decimal}]}
"#,
    )
    .unwrap();
    let mut owner = runtime();
    owner.configure_compiled(Some(Arc::new(policy))).unwrap();
    owner
}

#[test]
fn redis_key_scalar_formats_keep_keys_options_and_structured_json_strict() {
    let owner = scalar_runtime();
    for (command, source, target) in [
        ("SET", vec!["clock:1", "1010"], vec!["clock:1", "2010"]),
        (
            "HSET",
            vec!["clock:1", "at", "1010"],
            vec!["clock:1", "at", "2010"],
        ),
        ("RPUSH", vec!["clock:1", "1010"], vec!["clock:1", "2010"]),
        (
            "SET",
            vec!["clock:1", r#"{"at":1010}"#],
            vec!["clock:1", r#"{"at":2010}"#],
        ),
    ] {
        assert!(
            preview(&owner, command, &source, &target).is_ok(),
            "{command}"
        );
    }
    for (source, target) in [
        (vec!["clock:1", "1010"], vec!["clock:2", "2010"]),
        (
            vec!["clock:1", "1010", "EX", "30"],
            vec!["clock:1", "2010", "EX", "31"],
        ),
        (vec!["unselected", "1010"], vec!["unselected", "2010"]),
        (
            vec!["clock:1", r#"{"stable":1}"#],
            vec!["clock:1", r#"{"stable":2}"#],
        ),
        (vec!["clock:1", "1010"], vec!["clock:1", "\"2010\""]),
    ] {
        assert!(preview(&owner, "SET", &source, &target).is_err());
    }
    assert!(
        preview(
            &owner,
            "SET",
            &["clock:1", "invalid"],
            &["clock:1", "invalid"]
        )
        .is_ok()
    );
}

#[test]
fn redis_scalar_and_json_identities_share_correspondences_without_source_pollution() {
    let owner = scalar_runtime();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    owner
        .observe_redis_compiled_source(&context, &json!({}), &args(&["text:1", "text-11"]))
        .unwrap();
    assert!(!owner.has_identities("case"));
    owner
        .commit(
            preview(
                &owner,
                "SET",
                &["text:1", "text-11"],
                &["text:1", "text-999"],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        preview(
            &owner,
            "SET",
            &["json", r#"{"id":"text-11"}"#],
            &["json", r#"{"id":"text-999"}"#]
        )
        .is_ok()
    );
    assert!(
        preview(
            &owner,
            "SET",
            &["json", r#"{"id":"text-11"}"#],
            &["json", r#"{"id":"text-998"}"#]
        )
        .is_err()
    );
    let source = bulk("text-11");
    let delivery = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &target,
            0,
            None,
            "GET",
            &args(&["text:1"]),
            &args(&["text:1"]),
            &source,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let now = DateTime::from_timestamp(2000, 0).unwrap();
    assert!(
        delivery
            .render_consistent(now, Some(&bulk("text-wrong")))
            .is_err()
    );
    assert_eq!(
        delivery
            .render_consistent(now, Some(&bulk("text-999")))
            .unwrap(),
        bulk("text-999")
    );
}

#[test]
fn scalar_time_read_provenance_requires_a_delivered_read_at_the_same_physical_key() {
    let owner = scalar_runtime();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "GET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    let keys = args(&["clock:1"]);
    let prepared = owner
        .prepare_redis_time_read(
            &context,
            &keys,
            &keys,
            &bulk("100"),
            DateTime::from_timestamp(1000, 0),
        )
        .unwrap()
        .unwrap();
    assert!(preview(&owner, "SET", &["clock:1", "100"], &["clock:1", "555"]).is_err());
    prepared
        .publish(&bulk("555"), DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    assert!(preview(&owner, "SET", &["clock:1", "100"], &["clock:1", "555"]).is_ok());
    assert!(preview(&owner, "SET", &["clock:2", "100"], &["clock:2", "555"]).is_err());
    assert!(preview(&owner, "SET", &["clock:1", "100"], &["clock:1", "556"]).is_err());
}

#[test]
fn redis_scripts_expose_only_known_structured_json_argv() {
    let owner = scalar_runtime();
    let a = r#"{"at":1010,"stable":true}"#;
    let b = r#"{"at":2010,"stable":true}"#;
    let source = ["script", "1", "physical-key", "42", a];
    assert!(
        preview(
            &owner,
            "EVALSHA",
            &source,
            &["script", "1", "physical-key", "42", b]
        )
        .is_ok()
    );
    for changed in [
        ["other", "1", "physical-key", "42", b],
        ["script", "1", "other-key", "42", b],
        ["script", "1", "physical-key", "43", b],
    ] {
        assert!(preview(&owner, "EVALSHA", &source, &changed).is_err());
    }
    assert!(redis_field_values("EVAL", &args(&["script", "2", "key"]), None).is_err());
    let argv = args(&["script", "0", a]);
    assert!(redis_field_values("EVAL", &argv, None).is_ok());
}

#[test]
fn complete_json_identity_keys_match_atomically_without_relaxing_native_arguments() {
    let owner = scalar_runtime();
    let source = ["text-11", r#"{"id":"text-11","stable":true}"#];
    let target = ["text-999", r#"{"id":"text-999","stable":true}"#];
    assert!(
        preview(
            &owner,
            "SET",
            &source,
            &["text-999", r#"{"id":"text-999","stable":false}"#]
        )
        .is_err()
    );
    assert!(!owner.has_identities("case"));
    let accepted = preview(&owner, "SET", &source, &target).unwrap();
    assert!(!owner.has_identities("case"));
    owner.commit(accepted).unwrap();
    assert!(preview(&owner, "GET", &["text-11"], &["text-999"]).is_ok());
    assert!(preview(&owner, "DEL", &["text-11"], &["text-999"]).is_ok());
    assert!(
        owner
            .project_known_redis_keys(
                "case",
                "GET",
                &args(&["prefix:text-11"]),
                &args(&["prefix:text-999"])
            )
            .unwrap()
            .is_none()
    );
    assert!(preview(&owner, "EXPIRE", &["text-11", "30"], &["text-999", "31"]).is_err());
    assert!(
        owner
            .project_known_redis_keys("case", "GET", &args(&["text-11"]), &args(&["text-998"]))
            .unwrap()
            .is_none()
    );
}

#[test]
fn all_digit_hex_identities_keep_text_wire_form_in_writes_reads_and_script_references() {
    let compiled = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\nredis:\n  keys:\n    'hex:*': {kind: identity, formats: [{hex: 32}]}\n",
    ).unwrap();
    let mut owner = runtime();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    let a = "11111111111111111111111111111111";
    let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    owner
        .commit(preview(&owner, "SET", &["hex:1", a], &["hex:1", b]).unwrap())
        .unwrap();
    assert!(
        preview(
            &owner,
            "EVALSHA",
            &["script", "1", "hex:1", a],
            &["script", "1", "hex:1", b]
        )
        .is_ok()
    );
    assert!(
        preview(
            &owner,
            "DELEX",
            &["hex:1", "IFEQ", a],
            &["hex:1", "IFEQ", b]
        )
        .is_ok()
    );
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let keys = args(&["hex:1"]);
    let prepared = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &target,
            0,
            None,
            "GET",
            &keys,
            &keys,
            &bulk(a),
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        prepared
            .render(DateTime::from_timestamp(2000, 0).unwrap())
            .unwrap(),
        bulk(b)
    );
    assert!(
        preview(
            &owner,
            "SET",
            &["hex:1", a],
            &["hex:1", &format!("\"{b}\"")]
        )
        .is_err()
    );
}
