use crate::policy::{
    TrafficPolicy,
    compiler::{compile_definition, decode_policy},
    parse_policy,
};
use serde_json::{Value, json};

fn policy(keys: Value) -> Value {
    json!({"format":"traffic-policy/v3", "source_revision":"source-v1",
        "redis":{"keys":keys},
        "rules":[]})
}

fn render_key_policy(policy: &TrafficPolicy) -> String {
    use crate::policy::authoring::{context, view};

    traffic_policy_document::authoring::render_policy(&view(policy), &context()).unwrap()
}

fn command_authoring() -> Value {
    json!({"key_format":{"kind":"time_window","seconds":60},"commands":["INCRBY"]})
}

#[test]
fn key_command_contract_and_scalar_format_roundtrip_without_resource_aliases() {
    let raw = policy(json!({
        "rate:*": command_authoring(),
        "current:*": {"kind":"identity","formats":["uuid"],"state":{"set":"transition"}}
    }));
    let document = decode_policy(&raw.to_string()).unwrap();
    let compiled = compile_definition(&document).unwrap();
    assert_eq!(compiled.native.len(), 1);
    assert_eq!(compiled.redis.as_ref().unwrap().keys.len(), 1);
    assert!(compiled.native[0].rule.selector.api.is_none());
    assert!(compiled.native[0].rule.selector.resource.is_none());
    let rendered = render_key_policy(&document);
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(authored["redis"].get("rules").is_none());
    assert_eq!(authored["redis"]["keys"]["rate:*"], command_authoring());
    assert_eq!(authored["redis"]["keys"]["current:*"]["kind"], "identity");
    assert_eq!(
        compile_definition(&decode_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );

    let mut with_resource = raw;
    with_resource["resources"] =
        json!({"other":{"protocol":"redis","endpoint":"other.test:6380","database":9}});
    let other = compile_definition(&decode_policy(&with_resource.to_string()).unwrap()).unwrap();
    assert_eq!(other.native[0].rule.id, compiled.native[0].rule.id);
    assert_eq!(other.native[0].fingerprint, compiled.native[0].fingerprint);
}

#[test]
fn retired_redis_state_permissions_are_rejected_during_authoring() {
    for entry in [
        json!({"state":{"append":"concatenate"}}),
        json!({"state":{"expire":"refresh"}}),
        json!({"state":{"get":"observe"}}),
        json!({"state":{"get":{"transient":["nil"]}}}),
        json!({"state":{"set":{"reduce":"last","fields":["/last_activity_at"]}}}),
        json!({"read_commutation":true}),
    ] {
        let document = policy(json!({"content:*":entry}));
        assert!(decode_policy(&document.to_string()).is_err(), "{document}");
    }
    for effect in [
        "redis_append_stream",
        "redis_expiry_refresh",
        "redis_read_observation",
        "redis_read_commutation",
        "redis_activity_refresh",
    ] {
        let raw = json!({"format":"traffic-policy/v3","rules":[{
            "id":"retired","match":{},"effect":{"kind":effect}
        }]});
        assert!(decode_policy(&raw.to_string()).is_err(), "{raw}");
    }
}

#[test]
fn invalid_key_declarations_are_rejected() {
    for keys in [
        json!({"content:*":{"read_back":true}}),
        json!({"content:*":{"kind":"identity","formats":["uuid"],"read_back":true}}),
        json!({"content:*":{"finite_sharing":{"operation":"HGET"}}}),
        json!({"content:*":{"state":{}}}),
        json!({"content:*":{"state":{"set":"unknown"}}}),
    ] {
        assert!(
            parse_policy(&policy(keys.clone()).to_string()).is_err(),
            "accepted {keys}"
        );
    }
    let duplicate = "format: traffic-policy/v3\nredis:\n  keys:\n    content: {kind: time, formats: [unix_seconds], formats: [unix_seconds]}\n";
    assert!(parse_policy(duplicate).is_err());
}

#[test]
fn supplied_plan_proof_stays_real_and_runtime_rendering_omits_it() {
    let mut raw = policy(json!({"rate:*":command_authoring()}));
    let missing = decode_policy(&raw.to_string()).unwrap();
    assert!(crate::policy::require_source_proofs(&missing).is_err());
    raw["redis"]["keys"]["rate:*"]["proof"] =
        json!({"source":"cache.py:10-20","fact":"Source updates the minute counter"});
    let documented = decode_policy(&raw.to_string()).unwrap();
    crate::policy::require_source_proofs(&documented).unwrap();
    assert_eq!(
        compile_definition(&missing).unwrap().fingerprints,
        compile_definition(&documented).unwrap().fingerprints
    );
    let rendered = render_key_policy(&documented);
    assert!(!rendered.contains("proof:"));
}

mod commands;
