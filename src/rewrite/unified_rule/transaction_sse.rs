//! Public encrypted SSE discovery/plan/apply and actual assertion regressions.
use super::*;
use crate::interaction::{
    model::{InputTranscript, Protocol},
    policy::InteractionPolicy,
};
use serde_json::Value;

const START: i64 = 1_792_108_800;
const PRIVATE: &str = "synthetic-private-delta";

fn proposal() -> Value {
    let identity =
        json!({"kind":"identity","prefix":"msg_","format":"decimal","binding":"assistant-subtask"});
    let time = json!({"request_time":"unix_seconds","clock_group":"response"});
    let fields = [
        ("response.created", json!({"/response/created_at":time})),
        ("response.in_progress", json!({"/response/created_at":time})),
        ("response.output_item.added", json!({"/item/id":identity})),
        ("response.output_text.delta", json!({"/item_id":identity})),
        ("response.output_item.done", json!({"/item/id":identity})),
        (
            "response.completed",
            json!({"/response/created_at":time,"/response/output/*/id":identity}),
        ),
    ];
    Value::Array(fields.into_iter().map(|(event, contract)| json!({
        "id":event,"surface":"api.response","match":{"api":"GET /api"},
        "when":{"request_body_json":{"/stream":{"equals":true}}},
        "slot":{"sse_data":event},"codec":"json","contract":contract,
        "proof":{"source":"responses.py:builder","fact":"Source derives message identity from a fresh subtask and reuses it across events; creation uses this HTTP request clock"}
    })).collect())
}

fn event(name: &str, data: Value, index: usize) -> Value {
    let envelope = json!({"event":name,"data":data.to_string(),"id":null,"retry":null});
    json!({"sequence":index+1,"offset_ms":index*10,"heartbeat":false,
        "message":{"kind":"text","data":envelope.to_string()}})
}

fn stream(target: bool) -> Value {
    let time = START + if target { 60 } else { 0 };
    let id = if target { "msg_5002" } else { "msg_101" };
    let other = if target { "msg_5003" } else { "msg_102" };
    let response = json!({"created_at":time,"id":"resp-stable","status":"in_progress","output":[]});
    let frames = [
        (
            "response.created",
            json!({"type":"response.created","response":response}),
        ),
        (
            "response.in_progress",
            json!({"type":"response.in_progress","response":response}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","item":{"id":id,"role":"assistant"}}),
        ),
        (
            "response.output_text.delta",
            json!({"type":"response.output_text.delta","item_id":id,"delta":PRIVATE}),
        ),
        (
            "response.output_item.done",
            json!({"type":"response.output_item.done","item":{"id":id,"text":PRIVATE}}),
        ),
        (
            "response.output_item.added",
            json!({"type":"response.output_item.added","item":{"id":other,"role":"assistant"}}),
        ),
        (
            "response.completed",
            json!({"type":"response.completed","response":{"created_at":time,"id":"resp-stable","status":"completed","output":[{"id":id,"text":PRIVATE},{"id":other,"text":"second"}]}}),
        ),
    ];
    let mut value = json!({"status":200,"headers":{"content-type":["text/event-stream"]},"body":raw_body(b""),
        "interaction":{"version":1,"protocol":"sse",
            "events":frames.into_iter().enumerate().map(|(i,(name,data))|event(name,data,i)).collect::<Vec<_>>(),
            "end":{"reason":"server_eof","offset_ms":100,"pending":[],"clean":true}}});
    value["interaction"]["events"].as_array_mut().unwrap().push(json!({"sequence":8,"offset_ms":80,"heartbeat":false,
        "message":{"kind":"text","data":json!({"event":null,"data":"[DONE]","id":null,"retry":null}).to_string()}}));
    if target {
        value["version"] = json!(1);
        value["request_sent_at"] = json!("2026-10-16T00:01:00Z");
    }
    value
}

fn options(fixture: &Fixture) -> crate::ResponseAssertionOptions {
    let dir = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    crate::ResponseAssertionOptions {
        case_id: "case-1".into(),
        request: dir.join("request.json"),
        expected_response: dir.join("expected-response.json"),
        actual_response: fixture.paths.replay.parent().unwrap().join("case-1.json"),
        policy: fixture.policy(),
    }
}

fn install(fixture: &Fixture, mut source: Value, mut target: Value) {
    let paths = options(fixture);
    crate::interaction::private::protect_output(&mut source, &paths.expected_response).unwrap();
    crate::interaction::private::protect_output(&mut target, &paths.actual_response).unwrap();
    fixture.replace_responses(source, target);
}

fn fixture() -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        crate::platform::encryption_key::load_or_create(root).unwrap();
        let path = source.join("apis/api/case-1/request.json");
        let mut request: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        request["body"] = body(json!({"stream":true}));
        request["interaction"] = json!(InputTranscript::new(
            Protocol::Sse,
            InteractionPolicy::default()
        ));
        crate::interaction::private::protect_request(&mut request, &path).unwrap();
        write(&path, request);
        vec![]
    });
    install(&fixture, stream(false), stream(true));
    write(&fixture.proposal, proposal());
    fixture.confirm();
    fixture
}

fn change_data(value: &mut Value, index: usize, change: impl FnOnce(&mut Value)) {
    let message = &mut value["interaction"]["events"][index]["message"]["data"];
    let mut envelope: Value = serde_json::from_str(message.as_str().unwrap()).unwrap();
    let mut data: Value = serde_json::from_str(envelope["data"].as_str().unwrap()).unwrap();
    change(&mut data);
    envelope["data"] = json!(data.to_string());
    *message = json!(envelope.to_string());
}

#[test]
fn sse_value_contracts_discover_plan_apply_and_assert_encrypted_messages() {
    let fixture = fixture();
    let paths = options(&fixture);
    let originals = [
        &paths.request,
        &paths.expected_response,
        &paths.actual_response,
    ]
    .map(|p| fs::read(p).unwrap());
    let evidence = fixture.evidence();
    let candidates = evidence.facts["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(
        |c| c["draft_rule"]["slot"]["sse_data"] == "response.created"
            && c["draft_rule"]["contract"]["/response/created_at"]["kind"] == "time"
    ));
    assert!(!candidates.iter().any(|c| c["mechanism"] == "identity"));
    let plan = fixture.plan().unwrap();
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["source_validations"],
        1
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
    for rule in proposal().as_array().unwrap() {
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["rules"][rule["id"].as_str().unwrap()],
            1
        );
    }
    assert_eq!(plan.traffic_e2e_report["verified"], false);
    assert!(!serde_json::to_string(&plan).unwrap().contains(PRIVATE));
    assert!(!serde_json::to_string(&evidence).unwrap().contains(PRIVATE));
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    let report = crate::assert_recorded_response(options(&fixture)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.applied_body_rule_ids.len(), 6);
    for (path, bytes) in [
        &paths.request,
        &paths.expected_response,
        &paths.actual_response,
    ]
    .into_iter()
    .zip(originals)
    {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn sse_value_contracts_keep_identity_time_remainder_and_lifecycle_strict() {
    let fixture = fixture();
    let plan = fixture.plan().unwrap();
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    for scenario in [
        "time",
        "time-type",
        "identity-reference",
        "identity-collapse",
        "prefix",
        "id-type",
        "decimal",
        "text",
        "presence",
        "extra",
        "missing",
        "order",
        "event",
        "sse-id",
        "retry",
        "duplicate-json",
        "binary",
        "unclean",
        "pending",
        "carrier",
        "clock",
    ] {
        let mut target = stream(true);
        match scenario {
            "time" => change_data(&mut target, 0, |v| {
                v["response"]["created_at"] = json!(START)
            }),
            "time-type" => change_data(&mut target, 0, |v| {
                v["response"]["created_at"] = json!((START + 60).to_string())
            }),
            "identity-reference" => {
                change_data(&mut target, 3, |v| v["item_id"] = json!("msg_5004"))
            }
            "identity-collapse" => {
                change_data(&mut target, 5, |v| v["item"]["id"] = json!("msg_5002"))
            }
            "prefix" => change_data(&mut target, 2, |v| v["item"]["id"] = json!("bad_5002")),
            "id-type" => change_data(&mut target, 2, |v| v["item"]["id"] = json!(5002)),
            "decimal" => change_data(&mut target, 2, |v| v["item"]["id"] = json!("msg_05002")),
            "text" => change_data(&mut target, 3, |v| v["delta"] = json!("changed")),
            "presence" => change_data(&mut target, 2, |v| {
                v["item"].as_object_mut().unwrap().remove("id");
            }),
            "extra" => {
                let event = target["interaction"]["events"][0].clone();
                target["interaction"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .push(event);
            }
            "missing" => {
                target["interaction"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "order" => target["interaction"]["events"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1),
            "event" | "sse-id" | "retry" | "duplicate-json" => {
                let message = &mut target["interaction"]["events"][0]["message"]["data"];
                let mut envelope: Value = serde_json::from_str(message.as_str().unwrap()).unwrap();
                match scenario {
                    "event" => envelope["event"] = json!("other"),
                    "sse-id" => envelope["id"] = json!("other"),
                    "retry" => envelope["retry"] = json!(2000),
                    _ => envelope["data"] = json!("{\"response\":{},\"response\":{}}"),
                };
                *message = json!(envelope.to_string());
            }
            "binary" => target["interaction"]["events"][0]["message"]["kind"] = json!("binary"),
            "unclean" => target["interaction"]["end"]["clean"] = json!(false),
            "pending" => target["interaction"]["end"]["pending"] = json!([42]),
            "carrier" => {
                target.as_object_mut().unwrap().remove("interaction");
            }
            "clock" => {
                target.as_object_mut().unwrap().remove("request_sent_at");
            }
            _ => unreachable!(),
        }
        let path = options(&fixture).actual_response;
        crate::interaction::private::protect_output(&mut target, &path).unwrap();
        write(&path, target);
        let checked = crate::assert_recorded_response(options(&fixture)).unwrap();
        assert!(!checked.passed, "{scenario}");
        assert!(!serde_json::to_string(&checked).unwrap().contains(PRIVATE));
        if scenario == "text" {
            assert!(
                checked
                    .differences
                    .iter()
                    .any(|d| d.pointer == "$interaction/events/3/sse/data/delta")
            );
        }
    }
}

#[test]
fn sse_value_contract_preflight_rejects_invalid_source_and_target_and_stale_evidence() {
    for scenario in [
        "source-time",
        "source-field",
        "source-id",
        "target-id",
        "target-time",
        "target-length",
        "target-clock",
        "stale-key",
        "stale-artifact",
    ] {
        let fixture = fixture();
        let mut source = stream(false);
        let mut target = stream(true);
        match scenario {
            "source-time" => change_data(&mut source, 0, |v| {
                v["response"]["created_at"] = json!(START - 100)
            }),
            "source-field" => change_data(&mut source, 0, |v| {
                v["response"].as_object_mut().unwrap().remove("created_at");
            }),
            "source-id" => change_data(&mut source, 2, |v| v["item"]["id"] = json!("msg_invalid")),
            "target-id" => change_data(&mut target, 3, |v| v["item_id"] = json!("msg_5004")),
            "target-time" => change_data(&mut target, 0, |v| {
                v["response"]["created_at"] = json!(START)
            }),
            "target-length" => {
                target["interaction"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .truncate(2);
            }
            "target-clock" => {
                target.as_object_mut().unwrap().remove("request_sent_at");
            }
            _ => {}
        }
        install(&fixture, source, target);
        if scenario.starts_with("stale") {
            let plan = fixture.plan().unwrap();
            if scenario == "stale-key" {
                fs::write(
                    fixture
                        .root()
                        .join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH),
                    crate::request_headers::generate_encryption_key().unwrap(),
                )
                .unwrap();
            } else {
                fs::write(options(&fixture).actual_response, b"{}").unwrap();
            }
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            let error = format!("{:#}", fixture.plan().unwrap_err());
            assert!(
                error.contains("SSE response contract failed"),
                "{scenario}: {error}"
            );
            assert!(!error.contains(PRIVATE));
            assert!(fixture.state().rule_plan.is_none());
        }
    }
}

#[test]
fn sse_source_self_validation_without_target_requires_fresh_replay() {
    let fixture = fixture();
    let mut assertions: Value =
        serde_json::from_slice(&fs::read(&fixture.paths.assertions).unwrap()).unwrap();
    assertions["cases"][0]["response"] = Value::Null;
    write(&fixture.paths.assertions, assertions);
    let plan = fixture.plan().unwrap();
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["source_validations"],
        1
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        0
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["missing_target_witnesses"],
        1
    );
    assert_eq!(plan.traffic_e2e_report["verified"], false);
}
