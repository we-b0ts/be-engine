//! SSE slots are explicit, disjoint from bodies and closed to unsupported codecs.
use super::*;

fn rule() -> serde_json::Value {
    serde_json::json!({"id":"item","surface":"api.response","match":{"api":"POST /responses"},
        "slot":{"sse_data":"response.output_item.added"},"codec":"json",
        "contract":{"/item/id":{"kind":"identity","prefix":"msg_","format":"decimal","binding":"subtask"}},
        "proof":{"source":"source.py:42","fact":"Source derives the message ID from a fresh subtask and repeats it across frames"}})
}

fn compile(rules: serde_json::Value) -> anyhow::Result<CompiledPolicy> {
    parse_and_compile_policy(&serde_yaml::to_string(
        &serde_json::json!({"format":POLICY_FORMAT,"rules":rules}),
    )?)
}

#[test]
fn sse_slot_round_trips_and_separates_event_and_body_ownership() {
    let a = rule();
    let mut b = a.clone();
    b["id"] = "other-event".into();
    b["slot"]["sse_data"] = "response.output_item.done".into();
    let mut body = a.clone();
    body["id"] = "body".into();
    body["slot"] = "body".into();
    body["contract"] = serde_json::json!({"/item/id":{"request_time":"unix_seconds"}});
    let result = compile(serde_json::json!([a, b, body])).unwrap();
    assert_eq!(result.rules.len(), 3);
    assert!(
        result
            .rules
            .iter()
            .any(|r| r.capabilities == [CapabilityId::Identity])
    );
    let document = TrafficPolicy {
        format: POLICY_FORMAT.into(),
        source_revision: None,
        rules: result
            .rules
            .into_iter()
            .map(|r| PolicyRule::Value(Box::new(r.rule)))
            .collect(),
    };
    let yaml = serde_yaml::to_string(&document).unwrap();
    assert_eq!(
        compile_policy(&document).unwrap(),
        parse_and_compile_policy(&yaml).unwrap()
    );
    let mut duplicate = rule();
    duplicate["id"] = "conflict".into();
    assert!(compile(serde_json::json!([rule(), duplicate])).is_err());
}

#[test]
fn sse_slots_reject_ambiguous_events_unsupported_bindings_and_delivery() {
    let mut variants = vec![];
    for event in ["", "response.*", "bad\nevent"] {
        let mut r = rule();
        r["slot"]["sse_data"] = event.into();
        variants.push(r);
    }
    let mut r = rule();
    r["slot"] = "body".into();
    variants.push(r);
    let mut r = rule();
    r["contract"]["/item/id"]["binding"] = "".into();
    variants.push(r);
    let mut r = rule();
    r["contract"]["/item/id"]["format"] = "string".into();
    variants.push(r);
    let mut r = rule();
    r["delivery"] = serde_json::json!({"rebase_time":["/item/id"]});
    variants.push(r);
    let mut r = rule();
    r["codec"] = serde_json::json!({"kind":"protobuf","fields":{"/item/id":{"field_path":[1],"field_type":"string"}}});
    variants.push(r);
    let mut r = rule();
    r["surface"] = "dependency.response".into();
    r["match"]["resource"] = serde_json::json!({"protocol":"http","endpoint":"example:80"});
    variants.push(r);
    for r in variants {
        assert!(compile(serde_json::json!([r.clone()])).is_err(), "{r}");
    }
    let mut r = rule();
    r["id"] = "other".into();
    r["slot"]["sse_data"] = "response.output_item.done".into();
    r["contract"]["/item/id"]["format"] = "uuid".into();
    assert!(compile(serde_json::json!([rule(), r])).is_err());
}
