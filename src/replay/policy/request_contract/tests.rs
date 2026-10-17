use super::*;
use serde_json::json;

pub(super) fn rule(redis: Value) -> ReplayDependencyRule {
    serde_json::from_value(json!({"id":"write-contract","protocol":"redis","target":{"host":"cache.test","port":6379},"case":{"method":"PUT","path":"/presence/*"},"source_evidence":"Presence:update uses current Unix seconds and preserves its expiry interval","redis":redis})).unwrap()
}
fn time_rule() -> ReplayDependencyRule {
    rule(
        json!({"key":{"prefix":"presence:","numeric":true},"commands":[
            {"command":"ZADD","argument_values":{"1":{"time":"preserve_relative","format":"unix_seconds"}}},
            {"command":"ZREMRANGEBYSCORE","argument_values":{"2":{"time":"preserve_relative","format":"unix_seconds"}}}
        ]}),
    )
}
pub(super) fn runtime(rule: ReplayDependencyRule) -> RequestContracts {
    let mut state = State::default();
    state.cases.insert(
        "case".into(),
        CaseAnchor {
            source_body: None,
            conditions: BTreeSet::new(),
            method: "PUT".into(),
            path: "/presence/1".into(),
            recorded: Some(DateTime::from_timestamp(1000, 0).unwrap()),
            actual: Some(DateTime::from_timestamp(2000, 0).unwrap()),
            dir: PathBuf::new(),
        },
    );
    RequestContracts {
        rules: Arc::new(vec![rule]),
        state: Arc::new(Mutex::new(state)),
        ..Default::default()
    }
}
pub(super) fn target() -> TargetKey {
    TargetKey {
        host: "cache.test".into(),
        port: 6379,
    }
}
pub(super) fn args(values: &[&str]) -> Vec<Vec<u8>> {
    values.iter().map(|v| v.as_bytes().to_vec()).collect()
}
fn check(
    runtime: &RequestContracts,
    command: &str,
    source: &[&str],
    actual: &[&str],
) -> Result<Decision> {
    runtime
        .preview_redis("case", &target(), 0, command, &args(source), &args(actual))
        .expect("scoped rule")
}

#[test]
fn fractional_times_use_independent_request_anchors_and_preserve_each_update_difference() {
    let rule = time_rule();
    validate(&rule).unwrap();
    let runtime = runtime(rule);
    assert!(
        check(
            &runtime,
            "ZREMRANGEBYSCORE",
            &["presence:1", "-inf", "1000.25"],
            &["presence:1", "-inf", "2000.25"]
        )
        .is_err()
    );
    for increment in [0.25, 1.75] {
        let source = (1090.0 + increment).to_string();
        let actual = (2090.0 + increment).to_string();
        let decision = check(
            &runtime,
            "ZADD",
            &["presence:1", &source, "active"],
            &["presence:1", &actual, "active"],
        )
        .unwrap();
        runtime.commit(decision);
        assert!(
            check(
                &runtime,
                "ZREMRANGEBYSCORE",
                &["presence:1", "-inf", &(1000.0 + increment).to_string()],
                &["presence:1", "-inf", &(2001.0 + increment).to_string()]
            )
            .is_err()
        );
        runtime.commit(
            check(
                &runtime,
                "ZREMRANGEBYSCORE",
                &["presence:1", "-inf", &(1000.0 + increment).to_string()],
                &["presence:1", "-inf", &(2000.0 + increment).to_string()],
            )
            .unwrap(),
        );
    }
    assert!(
        check(
            &runtime,
            "ZADD",
            &["presence:1", "1090.25", "active"],
            &["presence:1", "9999.25", "active"]
        )
        .is_err()
    );
    assert!(
        check(
            &runtime,
            "ZADD",
            &["presence:1", "1090.25", "active"],
            &["presence:1", "2090.25", "away"]
        )
        .is_err()
    );
    assert!(
        check(
            &runtime,
            "ZADD",
            &["presence:1", "1090.25", "active"],
            &["presence:2", "2090.25", "active"]
        )
        .is_err()
    );
    assert!(
        runtime
            .preview_redis(
                "other",
                &target(),
                0,
                "ZADD",
                &args(&["presence:1", "1090.25", "active"]),
                &args(&["presence:1", "2090.25", "active"])
            )
            .is_none()
    );
    assert_eq!(runtime.reports()[0].matches, 4);
}

fn jwt_rule() -> ReplayDependencyRule {
    let jwt = json!({"jwt":{"signing_key_source":{"kind":"target_env","name":"SECRET_KEY"},"algorithm":"HS256","relative_to":"/approved_at"}});
    let mut refresh = jwt.clone();
    refresh["jwt"]["dynamic_claims"] = json!(["/jti"]);
    rule(
        json!({"key":{"prefix":"session:"},"commands":[{"command":"SET","argument_values":{"1":{"json":{"/approved_at":{"time":"preserve_relative","format":"unix_seconds"},"/access_token":jwt,"/refresh_token":refresh}}}}]}),
    )
}
fn token(claims: Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap()
}
fn session(now: i64, nonce: &str) -> Value {
    json!({"approved_at":now,"access_token":token(json!({"sub":"user","exp":now+3600})),"refresh_token":token(json!({"sub":"user","exp":now+7200,"jti":nonce,"token_use":"refresh","cnf":{"jkt":"device"}})),"status":"approved"})
}
fn check_session(
    runtime: &RequestContracts,
    source: &Value,
    actual: &Value,
    expiry: &str,
) -> Result<Decision> {
    check(
        runtime,
        "SET",
        &["session:1", &source.to_string(), "EX", "300"],
        &["session:1", &actual.to_string(), "EX", expiry],
    )
}

#[test]
fn two_signed_jwts_and_json_time_are_validated_atomically_with_strict_stable_fields() {
    let rule = jwt_rule();
    validate(&rule).unwrap();
    let mut runtime = runtime(rule);
    runtime.keys = Arc::new(BTreeMap::from([
        (
            ("write-contract".into(), "/access_token".into()),
            crate::request_rules::keys::ResolvedSigningKey::for_test(b"secret"),
        ),
        (
            ("write-contract".into(), "/refresh_token".into()),
            crate::request_rules::keys::ResolvedSigningKey::for_test(b"secret"),
        ),
    ]));
    let source = session(1000, "d9428888-122b-4d10-9c62-0b7bdca327a1");
    let actual = session(2000, "bf54c745-3da7-4ebc-9c32-fda7fd5a9bd2");
    runtime.commit(check_session(&runtime, &source, &actual, "300").unwrap());
    assert!(check_session(&runtime, &source, &actual, "300").is_ok());
    assert!(check_session(&runtime, &source, &actual, "301").is_err());
    let mut changed = actual.clone();
    changed["status"] = json!("pending");
    assert!(check_session(&runtime, &source, &changed, "300").is_err());
    for claims in [
        json!({"sub":"other","exp":5600}),
        json!({"sub":"user","exp":5700}),
        json!({"sub":"user","exp":1999}),
        json!({"sub":"user","exp":5600,"iat":2100}),
    ] {
        let mut changed = actual.clone();
        changed["access_token"] = json!(token(claims));
        assert!(check_session(&runtime, &source, &changed, "300").is_err());
    }
    let mut changed = actual.clone();
    changed["access_token"] = json!(format!(
        "{}invalid",
        actual["access_token"].as_str().unwrap()
    ));
    assert!(check_session(&runtime, &source, &changed, "300").is_err());
    let mut changed = actual.clone();
    changed["approved_at"] = json!("2000");
    assert!(check_session(&runtime, &source, &changed, "300").is_err());
    let changed = session(2000, "c9f1f795-7467-4399-9508-183dcab9627d");
    assert!(check_session(&runtime, &source, &changed, "300").is_err());
    assert_eq!(runtime.reports()[0].matches, 1);
}

#[test]
fn selectors_reject_ambiguous_ownership_and_unbounded_time_or_json_fields() {
    let rule = time_rule();
    let mut document: super::super::config::ReplayPolicyDocument =
        serde_yaml::from_str("version: 3\nexpected_response: assertions_only\n").unwrap();
    document.dependency_rules = vec![rule.clone(), rule];
    document.dependency_rules[1].id = "other".into();
    assert!(validate_overlaps(&document).is_err());
    for tolerance in ["0s", "2s", "6s", "30s"] {
        let mut value = serde_json::to_value(time_rule()).unwrap();
        value["redis"]["commands"][0]["argument_values"]["1"]["tolerance"] = json!(tolerance);
        assert!(validate(&serde_json::from_value(value).unwrap()).is_err());
    }
    let mut value = serde_json::to_value(jwt_rule()).unwrap();
    value["redis"]["commands"][0]["argument_values"]["1"]["json"]["/refresh_token"]["jwt"]["dynamic_claims"] =
        json!(["/sub"]);
    assert!(validate(&serde_json::from_value(value).unwrap()).is_err());
}

#[test]
fn redis_rfc3339_request_times_preserve_offset_without_timezone_configuration() {
    let rule = rule(
        json!({"key":{"prefix":"streaming:","numeric":true},"commands":[
            {"command":"SET","argument_values":{"1":{"json":{"/updated_at":{"time":"preserve_relative","format":"rfc3339"}}}}}
        ]}),
    );
    validate(&rule).unwrap();
    let runtime = runtime(rule);
    let source = r#"{"updated_at":"1970-01-01T08:16:40+08:00","status":"running"}"#;
    for (time, passes) in [
        ("1970-01-01T08:33:20+08:00", true),
        ("1970-01-01T08:33:25+08:00", true),
        ("1970-01-01T08:33:25.000001+08:00", false),
        ("1970-01-01T08:16:40+08:00", false),
        ("invalid", false),
    ] {
        let actual = json!({"updated_at":time,"status":"running"}).to_string();
        assert_eq!(
            check(
                &runtime,
                "SET",
                &["streaming:1", source],
                &["streaming:1", &actual]
            )
            .is_ok(),
            passes,
            "{time}"
        );
    }
    let changed = r#"{"updated_at":"1970-01-01T08:33:20+08:00","status":"stopped"}"#;
    assert!(
        check(
            &runtime,
            "SET",
            &["streaming:1", source],
            &["streaming:1", changed]
        )
        .is_err()
    );
}

#[test]
fn script_argv_times_require_identity_keys_units_and_consistent_parameter_deltas() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let spec = rule(
        json!({"key":{"prefix":"presence:"},"commands":[{"command":"EVALSHA","script":{"sha1":sha},"argument_values":{
            "3":{"time":"preserve_relative","format":"unix_milliseconds"},
            "4":{"time":"preserve_relative","format":"unix_milliseconds"}
        }}]}),
    );
    validate(&spec).unwrap();
    let runtime = runtime(spec);
    let source = [sha, "1", "presence:1", "1000250", "1090250", "stable"];
    let actual = [sha, "1", "presence:1", "2000250", "2090250", "stable"];
    runtime.commit(check(&runtime, "EVALSHA", &source, &actual).unwrap());
    for (index, value) in [
        (0, "different-script"),
        (1, "2"),
        (2, "presence:2"),
        (3, "9999999"),
        (4, "2091250"),
        (5, "changed"),
    ] {
        let mut changed = actual;
        changed[index] = value;
        assert!(
            check(&runtime, "EVALSHA", &source, &changed).is_err(),
            "index {index}"
        );
    }
    // Another recorded script on the same key is outside this rule.
    let other = [
        "abcdef0123456789abcdef0123456789abcdef01",
        "1",
        "presence:1",
        "1000250",
        "1090250",
        "stable",
    ];
    assert!(
        runtime
            .preview_redis(
                "case",
                &target(),
                0,
                "EVALSHA",
                &args(&other),
                &args(&other)
            )
            .is_none()
    );
    let mut bad = serde_json::to_value(time_rule()).unwrap();
    bad["redis"]["commands"][0]["command"] = json!("EVALSHA");
    assert!(validate(&serde_json::from_value(bad).unwrap()).is_err());
}

#[test]
fn eval_matches_only_declared_script_digest_and_never_selects_keys_as_time() {
    use sha2::{Digest, Sha256};
    let script = "return ARGV[1]";
    let spec = rule(
        json!({"key":"presence:1","commands":[{"command":"EVAL","script":{"sha256":format!("{:x}",Sha256::digest(script.as_bytes()))},"argument_values":{"3":{"time":"preserve_relative","format":"unix_seconds"}}}]}),
    );
    validate(&spec).unwrap();
    let runtime = runtime(spec);
    assert!(
        check(
            &runtime,
            "EVAL",
            &[script, "1", "presence:1", "1000"],
            &[script, "1", "presence:1", "2000"]
        )
        .is_ok()
    );
    assert!(
        check(
            &runtime,
            "EVAL",
            &[script, "1", "presence:1", "1000"],
            &["return 1", "1", "presence:1", "2000"]
        )
        .is_err()
    );
    assert!(
        check(
            &runtime,
            "EVAL",
            &[script, "2", "presence:1", "1000", "fixed"],
            &[script, "2", "presence:1", "2000", "fixed"]
        )
        .is_err()
    );
    let mut missing_anchor = runtime;
    missing_anchor.state = Arc::new(Mutex::new(State::default()));
    assert!(
        missing_anchor
            .preview_redis(
                "case",
                &target(),
                0,
                "EVAL",
                &args(&[script, "1", "presence:1", "1000"]),
                &args(&[script, "1", "presence:1", "2000"])
            )
            .is_none()
    );
}

#[test]
fn rpush_timestamp_rules_compose_with_explicit_integer_id_captures() {
    use super::super::dynamic_values::{DynamicValueRule, DynamicValues};
    let time_rule = rule(
        json!({"key":"events","commands":[{"command":"RPUSH","argument_values":{"1":{"json":{"/timestamp":{"time":"preserve_relative","format":"unix_seconds"}}}}}]}),
    );
    let identity: DynamicValueRule = serde_json::from_value(json!({"id":"event-id","api":"/presence/*","value_type":"integer","targets":[{"host":"cache.test","port":6379}],"capture":{"protocol":"redis","target":{"host":"cache.test","port":6379},"database":0,"key":"events","command":"RPUSH","argument_index":1,"json_pointer":"/id"},"source_evidence":"Emitter:enqueue generates one integer ID shared by event references"})).unwrap();
    identity.validate().unwrap();
    let mut document: super::super::config::ReplayPolicyDocument =
        serde_yaml::from_str("version: 3\nexpected_response: assertions_only\n").unwrap();
    document.dependency_rules.push(time_rule.clone());
    document.dynamic_values.push(identity.clone());
    validate_overlaps(&document).unwrap();
    let dynamic = DynamicValues::new(
        vec![identity],
        BTreeMap::from([("case".into(), "/presence/1".into())]),
    );
    let runtime = runtime(time_rule);
    let source = args(&["events", r#"{"id":1,"timestamp":1000,"stable":"keep"}"#]);
    let actual = args(&["events", r#"{"id":9,"timestamp":2000,"stable":"keep"}"#]);
    let normalized = dynamic
        .redis(Some("case"), &target(), 0, "RPUSH", &source, &actual)
        .unwrap()
        .unwrap();
    let decision = runtime
        .preview_redis(
            "case",
            &target(),
            0,
            "RPUSH",
            &normalized.source,
            &normalized.actual,
        )
        .unwrap()
        .unwrap();
    dynamic.commit("case", normalized.decision);
    runtime.commit(decision);
    let changed = args(&["events", r#"{"id":10,"timestamp":2000,"stable":"keep"}"#]);
    assert!(
        dynamic
            .redis(Some("case"), &target(), 0, "RPUSH", &source, &changed)
            .unwrap()
            .is_err()
    );
    for body in [
        r#"{"id":9,"timestamp":9999,"stable":"keep"}"#,
        r#"{"id":9,"timestamp":2000,"stable":"changed"}"#,
    ] {
        let changed = args(&["events", body]);
        let normalized = dynamic
            .redis(Some("case"), &target(), 0, "RPUSH", &source, &changed)
            .unwrap()
            .unwrap();
        assert!(
            runtime
                .preview_redis(
                    "case",
                    &target(),
                    0,
                    "RPUSH",
                    &normalized.source,
                    &normalized.actual
                )
                .unwrap()
                .is_err()
        );
    }
    let mut overlap = document;
    let super::super::dynamic_values::DynamicValueCapture::Redis { json_pointer, .. } =
        &mut overlap.dynamic_values[0].capture
    else {
        unreachable!()
    };
    *json_pointer = Some("/timestamp".into());
    assert!(validate_overlaps(&overlap).is_err());
}

#[test]
fn script_json_microseconds_preserve_copies_and_strict_envelope() {
    let digest = "75f75be3d11e483c99c83f8b0b8836c2e2c5923b";
    let rule = rule(
        json!({"key":"metrics","commands":[{"command":"EVALSHA","script":{"sha1":digest},
        "argument_values":{
            "3":{"time":"preserve_relative","format":"unix_seconds"},
            "4":{"time":"preserve_relative","format":"unix_microseconds"},
            "5":{"json":{"/changed_at_us":{"time":"preserve_relative","format":"unix_microseconds"}}}
        }}]}),
    );
    validate(&rule).unwrap();
    let runtime = runtime(rule.clone());
    let source = args(&[
        digest,
        "1",
        "metrics",
        "1000.123456",
        "1000123456",
        r#"{"changed_at_us":1000123456,"failed":true,"reason_id":7}"#,
        "keep",
    ]);
    let actual = args(&[
        digest,
        "1",
        "metrics",
        "2000.123456",
        "2000123456",
        r#"{"changed_at_us":2000123456,"failed":true,"reason_id":7}"#,
        "keep",
    ]);
    assert!(
        runtime
            .preview_redis("case", &target(), 0, "EVALSHA", &source, &actual)
            .unwrap()
            .is_ok()
    );
    for (index, bad) in [
        (0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        (1, "2"),
        (2, "other"),
        (3, "2001.123456"),
        (4, "2000123457"),
        (
            5,
            r#"{"changed_at_us":2000123457,"failed":true,"reason_id":7}"#,
        ),
        (
            5,
            r#"{"changed_at_us":2000123456,"failed":false,"reason_id":7}"#,
        ),
        (
            5,
            r#"{"changed_at_us":2000123456,"changed_at_us":2000123456,"failed":true,"reason_id":7}"#,
        ),
        (5, r#"{"failed":true,"reason_id":7}"#),
        (6, "changed"),
    ] {
        let mut bad_args = actual.clone();
        bad_args[index] = bad.as_bytes().to_vec();
        assert!(
            runtime
                .preview_redis("case", &target(), 0, "EVALSHA", &source, &bad_args)
                .unwrap()
                .is_err(),
            "index {index}: {bad}"
        );
    }
    let mut selected_key = rule;
    let super::super::redis_value::RedisSelector::Requests(selector) =
        selected_key.redis.as_mut().unwrap()
    else {
        unreachable!()
    };
    let field = selector.commands[0].argument_values.remove(&5).unwrap();
    selector.commands[0].argument_values.insert(3, field);
    // With two KEYS, index 3 belongs to KEYS and cannot be normalized.
    let input = args(&[digest, "2", "metrics", "second", "1000123456", "keep"]);
    assert!(selector.commands[0].validate_arguments(&input).is_err());
}

#[test]
fn publish_time_contract_requires_exact_channel_and_only_present_source_fields() {
    let rule = rule(
        json!({"key":"events","commands":[{"command":"PUBLISH","argument_values":{"1":{"json":{
            "/data/0/completed_at":{"time":"preserve_relative","format":"iso8601_naive","utc_offset":"+00:00"}
        }}}}]}),
    );
    validate(&rule).unwrap();
    let runtime = runtime(rule.clone());
    let source = r#"{"event":"task:status","data":[{"completed_at":"1970-01-01T00:16:40","status":"COMPLETED"}]}"#;
    let actual = source.replace("00:16:40", "00:33:20");
    assert!(
        check(
            &runtime,
            "PUBLISH",
            &["events", source],
            &["events", &actual]
        )
        .is_ok()
    );
    for bad in [
        actual.replace("COMPLETED", "FAILED"),
        actual.replace("00:33:20", "00:33:26"),
        r#"{"event":"task:status","data":[{"status":"COMPLETED"}]}"#.into(),
    ] {
        assert!(check(&runtime, "PUBLISH", &["events", source], &["events", &bad]).is_err());
    }
    assert!(
        runtime
            .preview_redis(
                "case",
                &target(),
                0,
                "PUBLISH",
                &args(&["events", r#"{"event":"other"}"#]),
                &args(&["events", r#"{"event":"other"}"#])
            )
            .is_none()
    );
    let mut broad = rule;
    let super::super::redis_value::RedisSelector::Requests(selector) =
        broad.redis.as_mut().unwrap()
    else {
        unreachable!()
    };
    selector.key = serde_json::from_value(json!({"prefix":"event"})).unwrap();
    assert!(validate(&broad).is_err());
}

pub(super) mod clock_groups;
