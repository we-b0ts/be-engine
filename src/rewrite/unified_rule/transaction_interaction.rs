//! Mixed API evidence preserves encrypted streams while planning ordinary bodies.
use super::*;
use crate::interaction::{model::InputTranscript, model::Protocol, policy::InteractionPolicy};
use serde_json::Value;

const PRIVATE_EVENT: &str = "synthetic-private-stream-event";

fn proposal(_conditional: bool) -> Value {
    json!({"format":"traffic-policy/v2","json":{"fields":{
        "/created_at":{"kind":"time","formats":["unix_seconds"]},
        "/id":{"kind":"identity","formats":["uuid"]}
    }}})
}

fn tamper(value: &mut Value) {
    let text = value.as_str().unwrap();
    let index = text.len() - 4;
    let mut changed = text.to_owned();
    changed.replace_range(
        index..index + 1,
        if &text[index..index + 1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    *value = json!(changed);
}

fn stream(target: bool) -> Value {
    let mut output = json!({"status":200,"body":raw_body(b""),
        "headers":{"content-type":["text/event-stream"],"content-disposition":["attachment; filename=2026-10-16.txt"]},
        "interaction":{"version":1,"protocol":"sse","events":[
            {"sequence":1,"offset_ms":10,"heartbeat":false,"message":{"kind":"text","data":json!({"event":null,"data":PRIVATE_EVENT,"id":null,"retry":null}).to_string()}},
            {"sequence":2,"offset_ms":20,"heartbeat":false,"message":{"kind":"text","data":json!({"event":null,"data":"terminal","id":null,"retry":null}).to_string()}}
        ],"end":{"reason":"server_eof","offset_ms":30,"pending":[],"clean":true}}});
    if target {
        output["version"] = json!(1);
        output["request_sent_at"] = json!("2026-10-16T00:01:00Z");
    }
    output
}

fn mixed(scenario: &str) -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        crate::platform::encryption_key::load_or_create(root).unwrap();
        let ordinary = source.join("apis/api/case-1/request.json");
        let mut request: Value = serde_json::from_slice(&fs::read(&ordinary).unwrap()).unwrap();
        request["body"] = body(json!({"stream":false}));
        write(&ordinary, request);
        let case = source.join("apis/api/case-2");
        fs::create_dir_all(&case).unwrap();
        fs::write(case.join("dependencies.jsonl"), "").unwrap();
        let path = case.join("request.json");
        let mut request = json!({"timestamp":"2026-10-16T00:00:00Z","method":"GET","uri":"/api?private=query",
            "body":body(json!({"stream":true})),"headers":{},
            "interaction":InputTranscript::new(Protocol::Sse,InteractionPolicy::default())});
        crate::interaction::private::protect_request(&mut request, &path).unwrap();
        if scenario == "bad-request" {
            tamper(&mut request["body"]["data"]);
        }
        write(&path, request);
        vec![case]
    });
    fixture.replace_response_bodies(
        br#"{"created_at":1792108800,"id":"11111111-1111-4111-8111-111111111111"}"#,
        br#"{"created_at":1792108860,"id":"22222222-2222-4222-8222-222222222222"}"#,
    );
    let case = fixture
        .state()
        .case_source
        .clone()
        .unwrap()
        .join("apis/api/case-2");
    let target_path = fixture.paths.replay.parent().unwrap().join("case-2.json");
    let mut source = stream(false);
    let mut target = stream(true);
    crate::interaction::private::protect_output(&mut source, &case.join("expected-response.json"))
        .unwrap();
    crate::interaction::private::protect_output(&mut target, &target_path).unwrap();
    if scenario == "bad-source" {
        tamper(&mut source["interaction"]["events"][0]["message"]["data"]);
    }
    if scenario == "bad-target" {
        tamper(&mut target["interaction"]["events"][0]["message"]["data"]);
    }
    fixture.replace_case_responses("case-2", source, target);
    write(&fixture.proposal, proposal(false));
    fixture.confirm();
    fixture
}

fn options(fixture: &Fixture, case: &str) -> crate::ResponseAssertionOptions {
    let directory = fixture
        .state()
        .case_source
        .clone()
        .unwrap()
        .join("apis/api")
        .join(case);
    crate::ResponseAssertionOptions {
        case_id: case.into(),
        request: directory.join("request.json"),
        expected_response: directory.join("expected-response.json"),
        actual_response: fixture
            .paths
            .replay
            .parent()
            .unwrap()
            .join(format!("{case}.json")),
        policy: fixture.policy(),
    }
}

#[test]
fn interaction_rules_plan_apply_mixed_encrypted_evidence_without_claiming_stream_body_proof() {
    for conditional in [false, true] {
        let fixture = mixed("");
        write(&fixture.proposal, proposal(conditional));
        let paths = ["case-1", "case-2"]
            .into_iter()
            .flat_map(|case| {
                let options = options(&fixture, case);
                [
                    options.request,
                    options.expected_response,
                    options.actual_response,
                ]
            })
            .collect::<Vec<_>>();
        let original = paths
            .iter()
            .map(|path| fs::read(path).unwrap())
            .collect::<Vec<_>>();
        let planned = fixture.plan().unwrap();
        let report = &planned.traffic_e2e_report;
        assert_eq!(report["preflight"]["source_validations"], 1);
        assert_eq!(report["preflight"]["independent_target_validations"], 1);
        assert_eq!(report["preflight"]["rules"]["global.json"], 1);
        assert_eq!(report["verified"], false);
        assert!(
            !serde_json::to_string(report)
                .unwrap()
                .contains(PRIVATE_EVENT)
        );
        apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        for case in ["case-1", "case-2"] {
            let checked = crate::assert_recorded_response(options(&fixture, case)).unwrap();
            assert!(checked.passed, "{:?}", checked.differences);
            assert_eq!(checked.applied_body_rule_ids.is_empty(), case == "case-2");
        }
        for (path, bytes) in paths.iter().zip(original) {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}

#[test]
fn interaction_rules_keep_events_order_closure_headers_and_carriers_strict() {
    let fixture = mixed("");
    let planned = fixture.plan().unwrap();
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    for (scenario, pointer) in [
        ("value", "$interaction/events/0"),
        ("order", "$interaction/events/0"),
        ("extra", "$interaction/events/length"),
        ("missing", "$interaction/events/length"),
        ("unclean", "$interaction/end/clean"),
        ("closure", "$interaction/end/reason"),
        ("headers", "$headers/content-type"),
        ("carrier", "$interaction"),
    ] {
        let options = options(&fixture, "case-2");
        let mut target = stream(true);
        match scenario {
            "value" => target["interaction"]["events"][0]["message"]["data"] = json!("changed"),
            "order" => target["interaction"]["events"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1),
            "extra" => {
                let extra = target["interaction"]["events"][0].clone();
                target["interaction"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .push(extra);
            }
            "missing" => {
                target["interaction"]["events"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            "unclean" => target["interaction"]["end"]["clean"] = json!(false),
            "closure" => target["interaction"]["end"]["reason"] = json!("business_idle"),
            "headers" => target["headers"]["content-type"] = json!(["application/json"]),
            "carrier" => {
                target.as_object_mut().unwrap().remove("interaction");
            }
            _ => unreachable!(),
        }
        crate::interaction::private::protect_output(&mut target, &options.actual_response).unwrap();
        write(&options.actual_response, target);
        let checked = crate::assert_recorded_response(options).unwrap();
        assert!(!checked.passed);
        assert!(
            checked
                .differences
                .iter()
                .any(|diff| diff.pointer.starts_with(pointer)),
            "{scenario}: {:?}",
            checked.differences
        );
        assert!(checked.applied_body_rule_ids.is_empty());
    }
}

#[test]
fn interaction_rules_reject_private_evidence_tampering_and_stale_keys() {
    for scenario in ["bad-request", "bad-source", "bad-target", "changed-key"] {
        let fixture = mixed(scenario);
        if scenario == "changed-key" {
            let planned = fixture.plan().unwrap();
            fs::write(
                fixture
                    .root()
                    .join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH),
                crate::request_headers::generate_encryption_key().unwrap(),
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &planned.plan_id).is_err());
        } else {
            let error = format!("{:#}", fixture.plan().unwrap_err());
            assert!(error.contains("authentication failed"), "{error}");
            assert!(!error.contains(PRIVATE_EVENT));
            assert!(fixture.state().rule_plan.is_none());
        }
        assert!(
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                .unwrap()
                .rules
                .is_empty()
        );
    }
}

#[test]
fn interaction_rules_require_a_positive_ordinary_body_witness() {
    let fixture = mixed("");
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v2","json":{"fields":{"/absent":{"kind":"unordered"}}}}),
    );
    let error = format!("{:#}", fixture.plan().unwrap_err());
    assert!(
        error.contains("no complete Source witness") || error.contains("no Source witness"),
        "{error}"
    );
}

#[test]
fn interaction_rules_preserve_private_header_date_and_jwt_contracts() {
    let fixture = mixed("");
    let key = "synthetic-stream-header-signing-key";
    fs::write(
        fixture.root().join(".traffic-e2e/local/target.env"),
        format!("SECRET_KEY={key}\n"),
    )
    .unwrap();
    let mut state = fixture.state();
    state.replay_identity = Some(fingerprint::replay_identity(fixture.root()).unwrap());
    fixture.store().save(&state).unwrap();
    let proof = json!({"source":"responses.py:headers","fact":"Source formats the request date and signs request-relative validity in the response headers"});
    let when = json!({"request_body_json":{"/stream":{"equals":true}}});
    let mut rules = proposal(false);
    rules["rules"] = json!([
        json!({"id":"stream-date","match":{"api":"GET /api"},"when":when,
            "effect":{"kind":"response_header_date","header":"content-disposition","parameter":"filename","format":"%Y-%m-%d"},"proof":proof}),
        json!({"id":"stream-jwt","match":{"api":"GET /api"},"when":when,
            "effect":{"kind":"response_jwt","location":{"header":"x-state"},"algorithm":"HS256",
                "signing_key":{"kind":"startup","source":{"kind":"target_env","name":"SECRET_KEY"}}},"proof":proof}),
    ]);
    write(&fixture.proposal, rules);
    let response_paths = options(&fixture, "case-2");
    let mut source = stream(false);
    let mut target = stream(true);
    for (response, time) in [
        (&mut source, 1_792_108_800i64),
        (&mut target, 1_792_108_860i64),
    ] {
        let token = crate::request_rules::tests::token(
            json!({"sub":"same","iat":time,"exp":time+600}),
            key,
        );
        response["headers"]["x-state"] = json!([token]);
    }
    let mut encrypted_source = source.clone();
    let mut encrypted_target = target.clone();
    crate::interaction::private::protect_output(
        &mut encrypted_source,
        &response_paths.expected_response,
    )
    .unwrap();
    crate::interaction::private::protect_output(
        &mut encrypted_target,
        &response_paths.actual_response,
    )
    .unwrap();
    fixture.replace_case_responses("case-2", encrypted_source, encrypted_target);
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["source_validations"],
        2
    );
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["independent_target_validations"],
        2
    );
    for id in ["stream-date", "stream-jwt"] {
        assert_eq!(planned.traffic_e2e_report["preflight"]["rules"][id], 1);
    }
    assert!(!serde_json::to_string(&planned).unwrap().contains(key));
    apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    let checked = crate::assert_recorded_response(response_paths).unwrap();
    assert!(checked.passed, "{:?}", checked.differences);
    assert!(checked.applied_body_rule_ids.is_empty());
    for id in ["stream-date", "stream-jwt"] {
        assert!(
            checked
                .applied_header_rule_ids
                .iter()
                .any(|applied| applied == id)
        );
    }
    for bad_jwt in [false, true] {
        let options = options(&fixture, "case-2");
        let mut changed = target.clone();
        if bad_jwt {
            changed["headers"]["x-state"] = json!([crate::request_rules::tests::token(
                json!({"sub":"same","iat":1_792_108_860i64,"exp":1_792_109_460i64}),
                "wrong-signing-key"
            )]);
        } else {
            changed["headers"]["content-disposition"] =
                json!(["attachment; filename=2026-10-18.txt"]);
        }
        crate::interaction::private::protect_output(&mut changed, &options.actual_response)
            .unwrap();
        write(&options.actual_response, changed);
        assert!(!crate::assert_recorded_response(options).unwrap().passed);
    }
}
