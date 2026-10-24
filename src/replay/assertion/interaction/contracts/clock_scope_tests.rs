use super::*;
use serde_json::json;

fn rules(entity: bool) -> crate::policy::CompiledPolicy {
    let scope = if entity {
        json!({"binding":"block","relative_pointer":"../id"})
    } else {
        json!("array_element")
    };
    let declarations = if entity {
        vec![("created", "/block"), ("done", "/response/blocks/*")]
    } else {
        vec![("done", "/response/blocks/*")]
    };
    let rules=declarations.into_iter().map(|(event,prefix)|json!({
        "id":event,"surface":"api.response","match":{"api":"GET /stream"},
        "slot":{"sse_data":{"event":"message","json_type":event}},"codec":"json",
        "contract":{
            format!("{prefix}/timestamp"):{"relative_time":"unix_microseconds","clock_group":"row-7","clock_scope":scope},
            format!("{prefix}/id"):{"kind":"identity","binding":"block","prefix":"text-","format":"decimal"}
        },"proof":{"source":"blocks.py:stream","fact":"Each created entity carries one clock reused in its terminal copy"}
    })).collect::<Vec<_>>();
    crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v2","rules":rules}).to_string(),
    )
    .unwrap()
}

fn output(data: Vec<Value>) -> OutputObservation {
    let events = data
        .into_iter()
        .enumerate()
        .map(|(index, data)| {
            let message = WireMessage {
                kind: MessageKind::Text,
                data: json!({"event":null,"id":null,"retry":null,"data":data.to_string()})
                    .to_string(),
            };
            json!({"sequence":index+1,"offset_ms":index,"heartbeat":false,"message":message})
        })
        .collect::<Vec<_>>();
    serde_json::from_value(json!({"version":1,"protocol":"sse","events":events,"end":{"reason":"server_eof","offset_ms":10,"pending":[],"clean":true}})).unwrap()
}

fn times() -> crate::replay::assertion::RequestTimes {
    crate::replay::assertion::RequestTimes {
        source: Some("1970-01-01T00:00:10Z".parse().unwrap()),
        target: Some("1970-01-01T00:01:50Z".parse().unwrap()),
    }
}

#[test]
fn sse_entity_clocks_retain_multi_block_copy_relationships_across_frames() {
    let policy = rules(true);
    let source_blocks = json!([{"id":"text-1","timestamp":12_000_000,"text":"a"},{"id":"text-2","timestamp":13_000_000,"text":"b"}]);
    let target_blocks = json!([{"id":"text-101","timestamp":112_000_000,"text":"a"},{"id":"text-102","timestamp":113_500_000,"text":"b"}]);
    let events = |blocks: &Value| {
        vec![
            json!({"type":"created","block":blocks[0]}),
            json!({"type":"created","block":blocks[1]}),
            json!({"type":"done","response":{"blocks":blocks}}),
        ]
    };
    let source = output(events(&source_blocks));
    let target = output(events(&target_blocks));
    let selected = policy.rules.iter().collect::<Vec<_>>();
    let compare = |target: &OutputObservation| {
        super::super::compare_outputs(Some(&source), Some(target), &selected, times()).unwrap()
    };
    let checked = compare(&target);
    assert!(checked.passed(), "{:?}", checked.differences);
    let mut bad = events(&target_blocks);
    bad[2]["response"]["blocks"][1]["timestamp"] = json!(113_500_001);
    assert!(!compare(&output(bad)).passed());
    let mut bad = events(&target_blocks);
    bad.remove(0);
    assert!(!compare(&output(bad)).passed());
    let mut bad = events(&target_blocks);
    bad[2]["response"]["blocks"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(!compare(&output(bad)).passed());
}

#[test]
fn sse_wildcards_allow_empty_and_absent_source_fields_with_exact_target_shape() {
    let policy = rules(false);
    let selected = policy.rules.iter().collect::<Vec<_>>();
    for source_data in [
        json!({"type":"done","response":{"blocks":[]}}),
        json!({"type":"done","stable":1}),
    ] {
        let source = output(vec![source_data.clone()]);
        let checked =
            super::super::compare_outputs(Some(&source), Some(&source), &selected, times())
                .unwrap();
        assert!(checked.passed(), "{:?}", checked.differences);
        let mut target_data = source_data;
        target_data["response"] = json!({"blocks":[{"id":"text-101","timestamp":112_000_000}]});
        let target = output(vec![target_data]);
        assert!(
            !super::super::compare_outputs(Some(&source), Some(&target), &selected, times())
                .unwrap()
                .passed()
        );
    }
    let source = output(vec![
        json!({"type":"done","response":{"blocks":[{"id":"text-1","timestamp":12_000_000}]}}),
    ]);
    let target = output(vec![json!({"type":"done","response":{"blocks":[]}})]);
    assert!(
        !super::super::compare_outputs(Some(&source), Some(&target), &selected, times())
            .unwrap()
            .passed()
    );
}
