use super::*;

#[test]
fn global_sse_strategy_does_not_require_event_or_json_type_selectors() {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v2
json:
  fields:
    /item_id: {kind: identity, formats: [{prefix: msg_, hex: 2}]}
"#,
    )
    .unwrap();
    let frame = |event: &str, id: &str| {
        let raw = format!("event: {event}\ndata: {{\"item_id\":\"{id}\",\"stable\":true}}\n\n");
        let mut decoder = crate::interaction::stream::StreamDecoder::new(
            crate::interaction::model::Protocol::Sse,
            1024,
        )
        .unwrap();
        decoder.feed(raw.as_bytes()).unwrap().pop().unwrap().message
    };
    let source = frame("arbitrary", "msg_01");
    let target = frame("arbitrary", "msg_02");
    assert!(
        compare_message(
            &source,
            &target,
            compiled.global_json.as_ref(),
            Default::default(),
            "$interaction/events/0"
        )
        .passed()
    );
    let changed = frame("changed-envelope", "msg_02");
    assert!(
        !compare_message(
            &source,
            &changed,
            compiled.global_json.as_ref(),
            Default::default(),
            "$interaction/events/0"
        )
        .passed()
    );
}
