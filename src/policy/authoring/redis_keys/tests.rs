use crate::policy::{NativeEffect, compile_policy, parse_policy, render_policy};
use serde_json::{Value, json};

fn policy(keys: Value) -> Value {
    json!({"format":"traffic-policy/v2", "source_revision":"source-v1",
        "redis":{"database":0,"keys":keys},
        "resources":{"cache":{"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"default"},
            "tauth":{"protocol":"redis","endpoint":"tauth.test:7455","database":0}},
        "rules":[]})
}

#[test]
fn key_behaviors_compile_to_existing_owners_and_roundtrip_without_api_or_bindings() {
    let raw = policy(json!({
        "chat:streaming:*":{"resource":"cache","append_stream":true,"expiry_refresh":true},
        "chat:cancel:*":{"resource":"cache","read_commutation":true},
        "chat:streaming:text_block:*":{"resource":"cache","kind":"identity",
            "formats":[{"prefix":"text-","format":"decimal"}],"read_back":true},
        "token_v2":{"resource":"tauth","finite_sharing":{"operation":"HGET","hash_field":"3061639762"}}
    }));
    let document = parse_policy(&raw.to_string()).unwrap();
    let compiled = compile_policy(&document).unwrap();
    assert_eq!(compiled.native.len(), 5);
    assert_eq!(compiled.redis.as_ref().unwrap().keys.len(), 1);
    for rule in &compiled.native {
        assert!(rule.rule.selector.api.is_none());
        let resource = rule.rule.selector.resource.as_ref().unwrap();
        if matches!(rule.rule.effect, NativeEffect::FiniteSharing(_)) {
            assert_eq!(resource.endpoint.port, 7455);
            assert!(resource.username.is_none());
        } else {
            assert_eq!(resource.endpoint.port, 6379);
            assert_eq!(resource.username.as_deref(), Some("default"));
        }
    }
    let rendered = render_policy(&document).unwrap();
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(authored["redis"].get("rules").is_none());
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:*"]["append_stream"],
        true
    );
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:*"]["expiry_refresh"],
        true
    );
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:text_block:*"]["read_back"],
        true
    );
    for hidden in [
        "binding:",
        "capture:",
        "references:",
        "state_epochs:",
        "redis.key.",
        "api:",
        "proof:",
    ] {
        assert!(!rendered.contains(hidden), "{rendered}");
    }
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn ids_ignore_alias_spelling_and_map_order_and_database_can_come_from_the_root() {
    let mut first = policy(json!({"content:*":{"resource":"cache","append_stream":true}}));
    first["resources"]["cache"]
        .as_object_mut()
        .unwrap()
        .remove("database");
    let parsed = parse_policy(&first.to_string()).unwrap();
    let compiled = compile_policy(&parsed).unwrap();
    let mut second = first.clone();
    let resource = second["resources"]
        .as_object_mut()
        .unwrap()
        .remove("cache")
        .unwrap();
    second["resources"]["other_name"] = resource;
    second["redis"]["keys"]["content:*"]["resource"] = "other_name".into();
    assert_eq!(
        compile_policy(&parse_policy(&second.to_string()).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&parsed).unwrap()).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn malformed_and_duplicate_key_permissions_are_rejected() {
    for keys in [
        json!({"content:*":{"append_stream":true}}),
        json!({"content:*":{"resource":"missing","append_stream":true}}),
        json!({"content:*":{"resource":"cache","append_stream":false}}),
        json!({"content:*":{"resource":"cache","append_stream":"true"}}),
        json!({"content:*":{"resource":"cache","append_stream":true,"api":"POST /items"}}),
        json!({"*":{"resource":"cache","append_stream":true}}),
        json!({"a*b*c":{"resource":"cache","append_stream":true}}),
        json!({"content:*":{"resource":"cache","read_back":true}}),
        json!({"content:*":{"resource":"cache","kind":"time","formats":["unix_seconds"],"read_back":true}}),
        json!({"content:*":{"resource":"cache","finite_sharing":{"operation":"HGET"}}}),
        json!({"content:*":{"resource":"cache","append_stream":true},
            "content:part:*":{"resource":"cache","append_stream":true}}),
    ] {
        assert!(
            parse_policy(&policy(keys.clone()).to_string()).is_err(),
            "accepted {keys}"
        );
    }
    let duplicate = "format: traffic-policy/v2\nredis:\n  keys:\n    content: {resource: cache, append_stream: true, append_stream: true}\nresources:\n  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}\n";
    assert!(parse_policy(duplicate).is_err());
    let mut wrong_protocol = policy(json!({"content:*":{"resource":"cache","append_stream":true}}));
    wrong_protocol["resources"]["cache"] = json!({"protocol":"http","endpoint":"cache.test:80"});
    assert!(parse_policy(&wrong_protocol.to_string()).is_err());
}

#[test]
fn supplied_plan_proof_stays_real_and_runtime_rendering_omits_it() {
    let mut raw = policy(json!({"content:*":{"resource":"cache","append_stream":true}}));
    let missing = parse_policy(&raw.to_string()).unwrap();
    assert!(crate::policy::require_source_proofs(&missing).is_err());
    raw["redis"]["keys"]["content:*"]["proof"] =
        json!({"source":"cache.py:10-20","fact":"Source appends chunks in order"});
    let documented = parse_policy(&raw.to_string()).unwrap();
    crate::policy::require_source_proofs(&documented).unwrap();
    assert_eq!(
        compile_policy(&missing).unwrap().fingerprints,
        compile_policy(&documented).unwrap().fingerprints
    );
    assert!(!render_policy(&documented).unwrap().contains("proof:"));
}
