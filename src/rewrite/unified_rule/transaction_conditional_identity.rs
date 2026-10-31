//! Public planning validates conditional captures in an encrypted mixed-block trace.
use super::*;
use serde_json::Value;

fn proposal(operation: &str) -> Value {
    json!({"id":"text-block","match":{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},
        "operation":operation,"key":{"kind":"exact","value":"blocks:7"}},
        "effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":if operation=="LSET" {2}else{1},"json_pointer":"/id",
            "when":{"relative_pointer":"../type","equals":"text"},
            "copies":[{"pointer":"/content_key","template":"content:{value}"}],
            "derived_from":{"pointer":"/timestamp","prefix":"text-"}},
            "references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}}]},
        "proof":{"source":"blocks.py:create","fact":"Only text block IDs derive from their millisecond timestamp; later content operations reference that same identity"}})
}

fn event(command: &str, args: &[&str], sequence: usize) -> Value {
    json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,
        "database":0,"resp_version":2,"command":command,"args":args.iter().map(|v|raw_body(v.as_bytes())).collect::<Vec<_>>(),
        "response_kind":if command=="LSET" {"simple_string"}else{"integer"},"response":raw_body(if command=="LSET" {b"+OK\r\n"}else{b":1\r\n"}),"outcome":"response","replay_safe":true})
}

#[test]
fn conditional_identity_public_plan_apply_decrypts_source_conditions_and_preserves_originals() {
    check_plan_apply("RPUSH");
}

#[test]
fn lset_conditional_identity_public_plan_apply_preserves_source_and_requires_fresh_replay() {
    check_plan_apply("LSET");
}

fn check_plan_apply(operation: &str) {
    for stream in [true, false] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            crate::platform::encryption_key::load_or_create(root).unwrap();
            let case = source.join("apis/api/00000000-0000-4000-8000-000000000001");
            let path = case.join("request.json");
            let mut request: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            request["body"] = body(json!({"stream":stream}));
            request["interaction"] = json!(crate::interaction::model::InputTranscript::new(
                crate::interaction::model::Protocol::Sse,
                crate::interaction::policy::InteractionPolicy::default()
            ));
            crate::interaction::private::protect_request(&mut request, &path).unwrap();
            write(&path, request);
            let text = json!({"type":"text","id":"text-1000","timestamp":1000,"content_key":"content:text-1000"}).to_string();
            let thinking = json!({"type":"thinking","id":"thinking-abcdef123456","timestamp":1000})
                .to_string();
            let tool = json!({"type":"tool","id":"toolu_owned","timestamp":1000}).to_string();
            let write = |element: &str, sequence| {
                let args = if operation == "LSET" {
                    vec!["blocks:7", "0", element]
                } else {
                    vec!["blocks:7", element]
                };
                event(operation, &args, sequence)
            };
            let events = [
                write(&thinking, 1),
                write(&tool, 2),
                write(&text, 3),
                event("APPEND", &["content:text-1000", "hello"], 4),
            ];
            fs::write(
                case.join("dependencies.jsonl"),
                events
                    .into_iter()
                    .map(|e| format!("{e}\n"))
                    .collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        write(&fixture.proposal, proposal(operation));
        fixture.confirm();
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001");
        let originals = [case.join("request.json"), case.join("dependencies.jsonl")]
            .map(|p| (p.clone(), fs::read(p).unwrap()));
        // The resource's local text discriminator applies regardless of the
        // encrypted inbound API body.
        let plan = fixture.plan().unwrap();
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["rules"]["text-block"],
            1
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["text-block"])
        );
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending);
        for (path, bytes) in originals {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}
