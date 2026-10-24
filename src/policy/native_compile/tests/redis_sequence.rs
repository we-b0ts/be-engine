use serde_json::{Value, json};

fn compile(field: Value) -> anyhow::Result<crate::policy::CompiledPolicy> {
    let document = json!({"format":"traffic-policy/v2","rules":[{
        "id":"generated","match":{"api":"POST /queue","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"key":{"kind":"exact","value":"queue"}},
        "effect":{"kind":"redis_sequence","commands":[{"operation":"LPUSH","arguments":{"1":{"kind":"json","fields":{"/items/*/value":field}}}}]},
        "proof":{"source":"src/producer.rs:publish","fact":"Source generates the selected field for each queued item"}
    }]});
    crate::policy::compile_policy(&crate::policy::parse_policy(&document.to_string())?)
}

#[test]
fn redis_random_shapes_require_closed_encodings_and_explicit_nonconflicting_bounds() {
    for valid in [
        json!({"kind":"random","format":"hex","length":64}),
        json!({"kind":"random","format":"base64url","length":43}),
        json!({"kind":"random","format":"uuid","length":36}),
        json!({"kind":"random","format":"string","max_length":255}),
    ] {
        assert!(compile(valid.clone()).is_ok(), "{valid}");
    }
    for invalid in [
        json!({"kind":"random","format":"uuid","length":32}),
        json!({"kind":"random","format":"uuid"}),
        json!({"kind":"random","format":"string","length":255}),
        json!({"kind":"random","format":"string","max_length":0}),
        json!({"kind":"random","format":"string","max_length":1025}),
        json!({"kind":"random","format":"hex","length":64,"max_length":64}),
        json!({"kind":"random","format":"base64","length":44}),
    ] {
        assert!(compile(invalid.clone()).is_err(), "{invalid}");
    }
}

#[test]
fn url_date_scope_requires_a_selected_time_and_inherits_source_proof() {
    let mut url = json!({"kind":"url","query":{
        "X-Amz-Date":{"kind":"time","format":"amz_date","relation":"preserve_offset"},
        "X-Amz-Signature":{"kind":"random","format":"hex","length":64},
        "X-Amz-Credential":{"kind":"utc_date_segment","separator":"/","index":1,"relative_to":"X-Amz-Date"}
    }});
    let compiled = compile(url.clone()).unwrap();
    let document = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v2","rules":[compiled.native[0].rule]}).to_string(),
    )
    .unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    // Runtime rendering preserves query semantics and excludes plan proof metadata.
    assert_eq!(
        crate::policy::compile_policy(&crate::policy::parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compiled.fingerprints
    );
    url["query"]["X-Amz-Credential"]["relative_to"] = json!("missing");
    assert!(compile(url).is_err());
}
