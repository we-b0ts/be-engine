use super::*;

const IDENTITY_POLICY: &str = r#"format: traffic-policy/v2
resources:
  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}
json:
  fields:
    /id: {kind: identity, formats: [decimal]}
    /peer: {kind: identity, formats: [decimal]}
    /at: {kind: time, formats: [unix_seconds]}
"#;

fn identity_runtime() -> RequestContracts {
    let policy = crate::policy::parse_and_compile_policy(IDENTITY_POLICY).unwrap();
    let mut owner = runtime();
    owner.configure_compiled(Some(Arc::new(policy))).unwrap();
    owner
}

fn native_runtime(rule: Value) -> RequestContracts {
    let mut document: Value = serde_yaml::from_str(IDENTITY_POLICY).unwrap();
    document["rules"] = json!([rule]);
    let compiled = crate::policy::parse_and_compile_policy(&document.to_string()).unwrap();
    let projection =
        crate::replay::policy::native_projection::project_native(&compiled.native).unwrap();
    let mut owner = identity_runtime();
    owner.rules = Arc::new(projection.document.dependency_rules);
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner
}

fn bind(owner: &RequestContracts) {
    owner
        .commit(
            preview(
                owner,
                "SET",
                &["session:1", r#"{"id":"11","stable":true}"#],
                &["session:1", r#"{"id":"999","stable":true}"#],
            )
            .unwrap(),
        )
        .unwrap();
}

fn delivery(
    owner: &RequestContracts,
    command: &str,
    values: &[&str],
    response: &[u8],
) -> super::super::super::unified_response::PreparedRedisDelivery {
    owner
        .prepare_redis_delivery(
            "case",
            "case",
            &TargetKey {
                host: "cache.test".into(),
                port: 6379,
            },
            0,
            None,
            command,
            &args(values),
            &args(values),
            response,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap()
}

#[test]
fn identities_span_commands_and_reject_equality_changes_and_collapses() {
    let owner = identity_runtime();
    let source = r#"{"id":"11","stable":true}"#;
    assert!(
        preview(
            &owner,
            "SET",
            &["session:1", source],
            &["session:1", r#"{"id":"91","stable":false}"#]
        )
        .is_err()
    );
    assert!(!owner.has_identities("case"));
    bind(&owner);
    for (command, a, b) in [
        (
            "HSET",
            vec!["hash:1", "field", source],
            vec!["hash:1", "field", r#"{"id":"999","stable":true}"#],
        ),
        (
            "RPUSH",
            vec!["list:1", source],
            vec!["list:1", r#"{"id":"999","stable":true}"#],
        ),
    ] {
        assert!(preview(&owner, command, &a, &b).is_ok());
    }
    assert!(
        preview(
            &owner,
            "SET",
            &["session:2", source],
            &["session:2", r#"{"id":"91","stable":true}"#]
        )
        .is_err()
    );
    assert!(
        preview(
            &owner,
            "SET",
            &["session:2", r#"{"id":"22","stable":true}"#],
            &["session:2", r#"{"id":"999","stable":true}"#]
        )
        .is_err()
    );
    assert!(
        preview(
            &owner,
            "MSET",
            &["session:2", r#"{"id":"22"}"#, "session:3", r#"{"id":"33"}"#],
            &["session:2", r#"{"id":"92"}"#, "session:3", r#"{"id":"92"}"#]
        )
        .is_err()
    );
}

#[test]
fn reads_deliver_known_target_ids_and_anchor_unknown_historical_ids() {
    let owner = identity_runtime();
    bind(&owner);
    let source = r#"{"id":"11","stable":true}"#;
    let original = bulk(source);
    let prepared = delivery(&owner, "GET", &["session:1"], &original);
    let rendered = prepared
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    assert_eq!(
        redis_bulk_payload(&rendered).unwrap().unwrap(),
        br#"{"id":"999","stable":true}"#
    );
    assert_eq!(original, bulk(source));
    let original = array(&[bulk("field"), bulk(r#"{"id":"22"}"#)]);
    let prepared = delivery(&owner, "HGETALL", &["hash:1"], &original);
    assert_eq!(
        prepared
            .render(DateTime::from_timestamp(2000, 0).unwrap())
            .unwrap(),
        original
    );
    assert!(
        preview(
            &owner,
            "SET",
            &["session:2", r#"{"id":"22"}"#],
            &["session:2", r#"{"id":"92"}"#]
        )
        .is_err()
    );
}

#[test]
fn source_self_validation_does_not_anchor_generated_values() {
    let owner = identity_runtime();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    let event = json!({"timestamp":"1970-01-01T00:16:40Z"});
    owner
        .observe_redis_compiled_source(&context, &event, &args(&["session:1", r#"{"id":"11"}"#]))
        .unwrap();
    assert!(!owner.has_identities("case"));
    bind(&owner);
}

#[test]
fn global_identity_and_time_compose_with_native_json_ownership() {
    let owner = native_runtime(json!({
        "id":"native-clock",
        "match":{"api":"POST /sessions", "resource":"cache", "key":{"kind":"affix","prefix":"session:","suffix":""}},
        "effect":{"kind":"redis_sequence", "commands":[{"operation":"SET", "arguments":{"1":{"kind":"json", "fields":{
            "/at":{"kind":"time","format":"unix_seconds","relation":"preserve_offset"}
        }}}}]},
        "proof":{"source":"app/cache.rs:1", "fact":"The contextual operation also validates the native timestamp"}
    }));
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    let source = args(&["session:1", r#"{"at":1010,"id":"11","stable":true}"#]);
    let actual = args(&["session:1", r#"{"at":2010,"id":"91","stable":true}"#]);
    let decision = owner
        .preview_redis_context(&context, &source, &actual)
        .unwrap()
        .unwrap();
    owner.commit(decision).unwrap();
    for changed in [
        r#"{"at":2010,"id":"92","stable":true}"#,
        r#"{"at":2010,"id":"91","stable":false}"#,
        r#"{"at":2100,"id":"91","stable":true}"#,
    ] {
        assert!(
            owner
                .preview_redis_context(&context, &source, &args(&["session:1", changed]))
                .unwrap()
                .is_err(),
            "invalid candidate was accepted: {changed}"
        );
    }
}

#[test]
fn native_key_only_contract_uses_global_value_fields_and_keeps_options_exact() {
    let owner = native_runtime(json!({
        "id":"native-key",
        "match":{"api":"POST /sessions", "resource":"cache", "key":{"kind":"affix","prefix":"session:","suffix":""}},
        "effect":{
            "kind":"redis_sequence",
            "key":{"kind":"capture","template":"session:{value}","format":{"kind":"hex","bytes":2}},
            "commands":[{"operation":"SET","arguments":{}}]
        },
        "proof":{"source":"app/cache.rs:1", "fact":"The key contains a generated session slot; entity payload fields have resource contracts"}
    }));
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    let source = args(&[
        "session:aabb",
        r#"{"at":1010,"id":"11","stable":true}"#,
        "EX",
        "90",
    ]);
    let actual = args(&[
        "session:ccdd",
        r#"{"at":2010,"id":"91","stable":true}"#,
        "EX",
        "90",
    ]);
    let decision = owner
        .preview_redis_context(&context, &source, &actual)
        .unwrap()
        .unwrap();
    owner.commit(decision).unwrap();
    for changed in [
        args(&[
            "session:ccdd",
            r#"{"at":2010,"id":"92","stable":true}"#,
            "EX",
            "90",
        ]),
        args(&[
            "session:ccdd",
            r#"{"at":2010,"id":"91","stable":false}"#,
            "EX",
            "90",
        ]),
        args(&[
            "session:ccdd",
            r#"{"at":2010,"id":"91","stable":true}"#,
            "EX",
            "91",
        ]),
    ] {
        assert!(
            owner
                .preview_redis_context(&context, &source, &changed)
                .unwrap()
                .is_err()
        );
    }
}
