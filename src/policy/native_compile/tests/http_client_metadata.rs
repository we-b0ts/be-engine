use crate::policy::{self, NativeEffect};
use serde_json::{Value, json};

fn rule() -> Value {
    json!({"id":"sdk-metadata","match":{
        "resource":{"protocol":"http","endpoint":"client.test:8080"},
        "operation":"POST","path":"/responses"},
        "effect":{"kind":"http_client_metadata","headers":["x-stainless-lang","x-stainless-runtime"]},
        "proof":{"source":"sdk.py:headers; consumer.py:responses","fact":"SDK generates runtime metadata; the selected consumer never reads it"}})
}
fn compile(rules: Vec<Value>) -> anyhow::Result<policy::CompiledPolicy> {
    policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v1","rules":rules}).to_string(),
    )
}

#[test]
fn client_metadata_is_typed_and_owns_only_the_selected_headers() {
    let compiled = compile(vec![rule()]).unwrap();
    assert!(matches!(
        compiled.native[0].rule.effect,
        NativeEffect::HttpClientMetadata(_)
    ));
    let mut duplicate = rule();
    duplicate["id"] = json!("other");
    assert!(compile(vec![rule(), duplicate.clone()]).is_err());
    duplicate["match"]["path"] = json!("/other");
    assert!(compile(vec![rule(), duplicate]).is_ok());
    let mut timestamp = rule();
    timestamp["id"] = json!("timestamp");
    timestamp["effect"] = json!({"kind":"http_request","headers":{"x-stainless-lang":{"format":"unix_seconds","relation":"request_window"}}});
    assert!(compile(vec![rule(), timestamp]).is_err());
    let parsed =
        policy::parse_policy(&json!({"format":"traffic-policy/v1","rules":[rule()]}).to_string())
            .unwrap();
    assert_eq!(
        policy::parse_and_compile_policy(&policy::render_policy(&parsed).unwrap()).unwrap(),
        compiled
    );
}

#[test]
fn client_metadata_rejects_unbounded_scopes_unknown_names_and_security_headers() {
    for names in [
        json!([]),
        json!(["x-stainless-*"]),
        json!(["X-Stainless-Lang"]),
        json!(["x-stainless-lang", "x-stainless-lang"]),
        json!(["authorization"]),
        json!(["tenant-id"]),
        json!(["x-stainless-api-key"]),
        json!(["idempotency-key"]),
    ] {
        let mut value = rule();
        value["effect"]["headers"] = names;
        assert!(compile(vec![value]).is_err());
    }
    for name in ["resource", "operation", "path"] {
        let mut value = rule();
        value["match"].as_object_mut().unwrap().remove(name);
        assert!(compile(vec![value]).is_err(), "{name}");
    }
    let mut value = rule();
    value["effect"]["ignore_all"] = json!(true);
    assert!(compile(vec![value]).is_err());
}
