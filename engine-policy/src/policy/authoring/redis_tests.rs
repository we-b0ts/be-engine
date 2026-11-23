use crate::policy::{compile_policy, parse_policy, render_policy};
use serde_json::{Value, json};

fn native_redis() -> Value {
    json!({"id":"background-scan","match":{},
        "effect":{"kind":"process_owned","selector":{"protocol":"redis","ports":[6379],
            "operation":"HSCAN","keys":[{"kind":"exact","value":"content"}]}},
        "proof":{"source":"cache.py:1","fact":"Source background task scans the content hash"}})
}
fn header() -> Value {
    json!({"id":"date","match":{"api":"GET /items"},"effect":{"kind":"response_header_date","header":"content-disposition","parameter":"filename","format":"%Y-%m-%d"},
        "proof":{"source":"api.py:1","fact":"Source renders the current request date"}})
}
fn base() -> Value {
    json!({"format":"traffic-policy/v3","source_revision":format!("sha256:{}", "a".repeat(64))})
}

#[test]
fn redis_native_namespace_flattens_to_one_runtime_and_keeps_no_empty_scalar_policy() {
    let mut flat = base();
    flat["rules"] = json!([native_redis(), header()]);
    let mut nested = base();
    nested["redis"] = json!({"rules":[native_redis()]});
    nested["rules"] = json!([header()]);
    let flat = parse_policy(&flat.to_string()).unwrap();
    let nested = parse_policy(&nested.to_string()).unwrap();
    assert_eq!(flat, nested);
    assert!(nested.redis.is_none());
    let compiled = compile_policy(&nested).unwrap();
    assert_eq!(compiled.native.len(), 2);
    assert!(compiled.redis.is_none());
    let rendered = render_policy(&nested).unwrap();
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(authored["redis"]["rules"].as_array().unwrap().len(), 1);
    assert_eq!(authored["rules"].as_array().unwrap().len(), 1);
    assert!(authored["redis"].get("keys").is_none());
    assert!(!rendered.contains("proof:"));
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn redis_scalar_settings_and_process_rules_share_author_section_without_duplicate_ownership() {
    let mut raw = base();
    raw["redis"] = json!({"keys":{"as-of":{"kind":"time","formats":["unix_seconds"]}},"rules":[native_redis()]});
    let policy = parse_policy(&raw.to_string()).unwrap();
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.redis.as_ref().unwrap().keys.len(), 1);
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&policy).unwrap()).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&policy).unwrap().fingerprints
    );
    raw["rules"] = json!([native_redis()]);
    assert!(parse_policy(&raw.to_string()).is_err());
    for invalid in [
        "format: traffic-policy/v3\nredis: {rules: null}\n",
        "format: traffic-policy/v3\nredis: {rules: [], unknown: true}\n",
        "format: traffic-policy/v3\nredis:\n  keys:\n    same: {kind: time, formats: [unix_seconds]}\n    same: {kind: time, formats: [unix_seconds]}\n  rules: []\n",
    ] {
        assert!(parse_policy(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn redis_process_ownership_stays_under_redis_without_changing_its_scope() {
    let mut raw = base();
    raw["source_revision"] = format!("sha256:{}", "a".repeat(64)).into();
    raw["rules"] = json!([{
        "id":"background-scan", "match":{},
        "effect":{"kind":"process_owned", "selector":{"protocol":"redis",
            "ports":[6379], "operation":"HSCAN",
            "keys":[{"kind":"numeric", "prefix":"inbox:", "suffix":""}]}}
    }]);
    let policy = parse_policy(&raw.to_string()).unwrap();
    let rendered = render_policy(&policy).unwrap();
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert_eq!(authored["redis"]["rules"].as_array().unwrap().len(), 1);
    assert!(authored.get("rules").is_none());
    assert_eq!(
        authored["redis"]["rules"][0]["effect"]["selector"]["operation"],
        "HSCAN"
    );
    assert_eq!(
        compile_policy(&policy).unwrap().fingerprints,
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints
    );
}
