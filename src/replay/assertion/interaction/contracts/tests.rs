use super::*;
use serde_json::json;

fn message(kind: &str, id: &str) -> WireMessage {
    let bytes = format!("data: {}\n\n", json!({"type":kind,"id":id}));
    let mut decoder = crate::interaction::stream::StreamDecoder::new(Protocol::Sse, 1024).unwrap();
    let mut messages = decoder.feed(bytes.as_bytes()).unwrap();
    decoder.finish().unwrap();
    messages.pop().unwrap().message
}

#[test]
fn broad_rule_cannot_relax_a_selected_json_type_discriminator() {
    let identity = |prefix: &str, binding: &str| json!({"kind":"identity","prefix":prefix,"format":{"hex":2},"binding":binding});
    let rules = [
        ("typed", json!({"sse_data":{"event":"message","json_type":"kind_ab"}}),
            json!({"/id":identity("msg_", "message")})),
        ("broad", json!({"sse_data":"message"}),
            json!({"/type":identity("kind_", "type")})),
    ].map(|(id,slot,contract)| json!({"id":id,"surface":"api.response","match":{"api":"GET /api"},
        "slot":slot,"codec":"json","contract":contract,
        "proof":{"source":"synthetic.py:1","fact":"Synthetic identity generation for strict discriminator regression"}}));
    let compiled = crate::policy::parse_and_compile_policy(
        &serde_yaml::to_string(&json!({"format":"traffic-policy/v1","rules":rules})).unwrap(),
    )
    .unwrap();
    let selected = compiled.rules.iter().collect::<Vec<_>>();
    let source = message("kind_ab", "msg_01");
    assert!(
        compare_message(
            &source,
            &message("kind_ab", "msg_02"),
            &selected,
            Default::default(),
            "$interaction/events/0"
        )
        .passed()
    );
    let changed = compare_message(
        &source,
        &message("kind_cd", "msg_02"),
        &selected,
        Default::default(),
        "$interaction/events/0",
    );
    assert!(!changed.passed());
    assert!(
        changed
            .differences
            .iter()
            .any(|d| d.pointer == "$interaction/events/0/sse/data/type")
    );
    // A Target type alone never activates the Source-only selector.
    let typed_only = selected
        .into_iter()
        .filter(|r| r.rule.id == "typed")
        .collect::<Vec<_>>();
    assert!(
        !compare_message(
            &message("other", "msg_01"),
            &message("kind_ab", "msg_02"),
            &typed_only,
            Default::default(),
            "$interaction/events/0"
        )
        .passed()
    );
}
