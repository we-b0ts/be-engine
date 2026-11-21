use crate::policy::{
    TrafficPolicy,
    compiler::{compile_definition, decode_policy},
};
use crate::policy::{compile_policy, parse_policy, render_policy};
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

#[test]
fn key_behaviors_compile_to_existing_owners_and_roundtrip_without_api_or_bindings() {
    let raw = policy(json!({
        "chat:streaming:*":{"state":{"append":"concatenate","expire":"refresh"}},
        "chat:cancel:*":{"read_commutation":true},
        "task:cancel:*":{"state":{"get":{"transient":["nil"]}}},
        "chat:streaming:text_block:*":{"kind":"identity",
            "formats":[{"prefix":"text-","format":"decimal"}]}
    }));
    let document = decode_policy(&raw.to_string()).unwrap();
    let compiled = compile_definition(&document).unwrap();
    assert_eq!(compiled.native.len(), 4);
    assert_eq!(compiled.redis.as_ref().unwrap().keys.len(), 1);
    for rule in &compiled.native {
        assert!(rule.rule.selector.api.is_none());
        assert!(rule.rule.selector.resource.is_none());
    }
    let rendered = render_key_policy(&document);
    let authored: Value = serde_yaml::from_str(&rendered).unwrap();
    assert!(authored["redis"].get("rules").is_none());
    assert_eq!(
        authored["redis"]["keys"]["task:cancel:*"]["state"]["get"]["transient"],
        json!(["nil"])
    );
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:*"]["state"]["append"],
        "concatenate"
    );
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:*"]["state"]["expire"],
        "refresh"
    );
    assert_eq!(
        authored["redis"]["keys"]["chat:streaming:text_block:*"]["kind"],
        "identity"
    );
    for hidden in [
        "binding:",
        "capture:",
        "references:",
        "redis.key.",
        "api:",
        "proof:",
    ] {
        assert!(!rendered.contains(hidden), "{rendered}");
    }
    assert_eq!(
        compile_definition(&decode_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
}

#[test]
fn global_key_permissions_do_not_depend_on_resource_aliases() {
    let first = policy(json!({"content:*":{"state":{"append":"concatenate"}}}));
    let parsed = parse_policy(&first.to_string()).unwrap();
    let compiled = compile_policy(&parsed).unwrap();
    let mut second = first.clone();
    second["resources"] = json!({"unrelated":{"protocol":"redis","endpoint":"other.test:6380","database":9,"username":"other"}});
    let other = compile_policy(&parse_policy(&second.to_string()).unwrap()).unwrap();
    assert_eq!(compiled.native[0].fingerprint, other.native[0].fingerprint);
    assert_eq!(compiled.native[0].rule.id, other.native[0].rule.id);
}

#[test]
fn malformed_and_duplicate_key_permissions_are_rejected() {
    for keys in [
        json!({"content:*":{"resource":"missing","state":{"append":"concatenate"}}}),
        json!({"content:*":{"database":0,"state":{"append":"concatenate"}}}),
        json!({"content:*":{"append_stream":false}}),
        json!({"content:*":{"read_observation":false}}),
        json!({"content:*":{"append_stream":"true"}}),
        json!({"content:*":{"state":{"append":"concatenate"},"api":"POST /items"}}),
        json!({"*":{"state":{"append":"concatenate"}}}),
        json!({"a*b*c":{"state":{"append":"concatenate"}}}),
        json!({"content:*":{"read_back":true}}),
        json!({"content:*":{"kind":"identity","formats":["uuid"],"read_back":true}}),
        json!({"content:*":{"finite_sharing":{"operation":"HGET"}}}),
        json!({"content:*":{"state":{"append":"concatenate"}},
            "content:part:*":{"state":{"append":"concatenate"}}}),
    ] {
        assert!(
            parse_policy(&policy(keys.clone()).to_string()).is_err(),
            "accepted {keys}"
        );
    }
    let duplicate = "format: traffic-policy/v3\nredis:\n  keys:\n    content: {resource: cache, append_stream: true, append_stream: true}\nresources:\n  cache: {protocol: redis, endpoint: 'cache.test:6379', database: 0}\n";
    assert!(parse_policy(duplicate).is_err());
    let named = policy(json!({"content:*":{"resource":"cache","state":{"append":"concatenate"}}}));
    assert!(parse_policy(&named.to_string()).is_err());
}

#[test]
fn supplied_plan_proof_stays_real_and_runtime_rendering_omits_it() {
    let mut raw = policy(json!({"content:*":{"state":{"append":"concatenate"}}}));
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

mod commands;
mod state;
