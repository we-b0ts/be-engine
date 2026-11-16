use super::*;
use crate::interaction::{
    model::{EndObservation, EndReason, InputAction, OutputEvent},
    policy::InteractionPolicy,
};
use serde_json::json;

mod wire;

fn input() -> InputTranscript {
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    input.actions = [(936, 30_000), (811, 40_000)]
        .into_iter()
        .enumerate()
        .map(|(i, (id, offset_ms))| InputAction {
            sequence: i as u64 + 1,
            offset_ms,
            offset_us: None,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(format!("42/n,{id}[\"heartbeat\",{{}}]")),
            },
        })
        .collect();
    input
}

fn output(messages: &[&str]) -> OutputObservation {
    OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol: Protocol::SocketIo,
        events: messages
            .iter()
            .enumerate()
            .map(|(i, message)| OutputEvent {
                sequence: i as u64 + 1,
                offset_ms: 41_000 + i as u64 * 1_000,
                heartbeat: false,
                message: WireMessage::text(*message),
            })
            .collect(),
        end: EndObservation {
            reason: EndReason::ClientClose,
            offset_ms: 42_000 + messages.len() as u64 * 1_000,
            pending: vec![],
            clean: true,
            missing_predecessor: None,
            dispatch_timeout: None,
            fast_heartbeat_eof_ms: None,
            partial_message: None,
            close: None,
        },
    }
}

const A: &str = r#"43/n,936[{"tag":"A"}]"#;
const B: &str = r#"43/n,811[{"tag":"B"}]"#;

#[test]
fn paired_ack_arguments_still_evaluate_global_field_contracts() {
    let policy = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson:\n  fields:\n    /id: {kind: identity, formats: [decimal]}\n",
    ).unwrap();
    let input = input();
    let context = Context::prepare(Some(&input)).unwrap().unwrap();
    let source = output(&[
        r#"43/n,936[{"id":"11","tag":"A"}]"#,
        r#"43/n,811[{"id":"22","tag":"B"}]"#,
    ]);
    let check = |a: &str, b: &str| {
        super::super::compare_outputs_global_with_time_copies(
            Some(&source),
            Some(&output(&[b, a])),
            policy.global_json.as_ref(),
            Default::default(),
            Default::default(),
            &Default::default(),
            Some(&context),
            false,
            8 * 1024 * 1024,
        )
        .unwrap()
    };
    let valid = check(
        r#"43/n,936[{"id":"111","tag":"A"}]"#,
        r#"43/n,811[{"id":"222","tag":"B"}]"#,
    );
    assert!(valid.passed(), "{:?}", valid.differences);
    assert!(!valid.evaluated.is_empty());
    assert!(
        !check(
            r#"43/n,936[{"id":"111","tag":"wrong"}]"#,
            r#"43/n,811[{"id":"222","tag":"B"}]"#
        )
        .passed()
    );
}

#[test]
fn public_response_assertion_prepares_context_before_consuming_the_request() {
    let root = tempfile::tempdir().unwrap();
    let request = root.path().join("request.json");
    let expected = root.path().join("expected-response.json");
    let actual = root.path().join("actual-response.json");
    let policy = root.path().join("policy.yaml");
    std::fs::write(
        &request,
        json!({"method":"GET","uri":"/socket.io/","interaction":input()}).to_string(),
    )
    .unwrap();
    let body = json!({"encoding":"utf8","data":"","truncated":false});
    std::fs::write(
        &expected,
        json!({"status":101,"headers":{},"body":body,"interaction":output(&[A,B])}).to_string(),
    )
    .unwrap();
    std::fs::write(
        &actual,
        json!({"version":1,"status":101,"headers":{},"body":body,"interaction":output(&[B,A])})
            .to_string(),
    )
    .unwrap();
    std::fs::write(&policy, "format: traffic-policy/v3\nrules: []\n").unwrap();
    let result = crate::assert_recorded_response(crate::ResponseAssertionOptions {
        case_id: "ack-proof".into(),
        request,
        expected_response: expected,
        actual_response: actual,
        policy,
    })
    .unwrap();
    assert!(result.passed, "{:?}", result.differences);
}
