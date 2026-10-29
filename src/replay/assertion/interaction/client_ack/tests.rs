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
                offset_ms: i as u64,
                heartbeat: false,
                message: WireMessage::text(*message),
            })
            .collect(),
        end: EndObservation {
            reason: EndReason::ClientClose,
            offset_ms: 50_000,
            pending: vec![],
            clean: true,
            partial_message: None,
            close: None,
        },
    }
}

const A: &str = r#"43/n,936[{"tag":"A"}]"#;
const B: &str = r#"43/n,811[{"tag":"B"}]"#;

fn checked(input: Option<&InputTranscript>, source: &[&str], target: &[&str]) -> Comparison {
    let context = Context::prepare(input).unwrap();
    super::super::compare_outputs_global_with_time_copies(
        Some(&output(source)),
        Some(&output(target)),
        None,
        Default::default(),
        &Default::default(),
        context.as_ref(),
    )
    .unwrap()
}

#[test]
fn independent_ack_arrival_order_keeps_exact_request_identity_and_distinct_bodies() {
    let input = input();
    assert!(checked(Some(&input), &[A, B], &[B, A]).passed());
    for target in [
        vec![r#"43/n,811[{"tag":"A"}]"#, r#"43/n,936[{"tag":"B"}]"#],
        vec![B, B],
        vec![B],
        vec![B, A, A],
        vec![B, r#"43/n,999[{"tag":"A"}]"#],
        vec![B, r#"43/other,936[{"tag":"A"}]"#],
        vec![B, r#"42/n,936["heartbeat",{"tag":"A"}]"#],
    ] {
        assert!(
            !checked(Some(&input), &[A, B], &target).passed(),
            "accepted {target:?}"
        );
    }
}

#[test]
fn ack_alignment_requires_unique_original_requests_and_fast_input_policy() {
    assert!(!checked(None, &[A, B], &[B, A]).passed());
    let mut timed = input();
    timed.policy.preserve_input_timing = true;
    assert!(!checked(Some(&timed), &[A, B], &[B, A]).passed());
    let mut unknown = input();
    unknown.actions.pop();
    assert!(!checked(Some(&unknown), &[A, B], &[B, A]).passed());
    let mut reused = input();
    let mut duplicate = reused.actions[0].clone();
    duplicate.sequence = 3;
    duplicate.offset_ms = 45_000;
    reused.actions.push(duplicate);
    assert!(!checked(Some(&reused), &[A, B], &[B, A]).passed());
}

#[test]
fn direct_and_transitive_completion_edges_prevent_ack_reordering() {
    let mut direct = input();
    direct.actions[1].after = vec![1];
    assert!(!checked(Some(&direct), &[A, B], &[B, A]).passed());
    let mut transitive = input();
    let mut middle = transitive.actions[0].clone();
    middle.sequence = 2;
    middle.offset_ms = 35_000;
    middle.after = vec![1];
    middle.action = InputActionKind::Message {
        message: WireMessage::text("3"),
    };
    transitive.actions[1].sequence = 3;
    transitive.actions[1].after = vec![2];
    transitive.actions.insert(1, middle);
    assert!(!checked(Some(&transitive), &[A, B], &[B, A]).passed());
    let mut siblings = input();
    let mut common = siblings.actions[0].clone();
    common.sequence = 1;
    common.offset_ms = 0;
    common.action = InputActionKind::Message {
        message: WireMessage::text("40/n,"),
    };
    for action in &mut siblings.actions {
        action.sequence += 1;
        action.after = vec![1];
    }
    siblings.actions.insert(0, common);
    assert!(
        checked(Some(&siblings), &[A, B], &[B, A]).passed(),
        "common predecessor is not a sibling ordering edge"
    );
}

#[test]
fn input_transport_and_namespace_boundaries_keep_reply_order_strict() {
    for message in ["41/n,", "40/n,", "1", "5"] {
        let mut separated = input();
        let mut control = separated.actions[0].clone();
        control.sequence = 2;
        control.offset_ms = 35_000;
        control.action = InputActionKind::Message {
            message: WireMessage::text(message),
        };
        separated.actions[1].sequence = 3;
        separated.actions.insert(1, control);
        assert!(
            !checked(Some(&separated), &[A, B], &[B, A]).passed(),
            "crossed input {message}"
        );
    }
}

#[test]
fn ack_pairing_never_crosses_output_events_namespace_controls_or_binary_frames() {
    let input = input();
    for barrier in [
        r#"42/n,["notice",{}]"#,
        r#"40/n,{"sid":"live"}"#,
        "41/n,",
        r#"451-/n,["binary",{"_placeholder":true,"num":0}]"#,
    ] {
        assert!(
            !checked(Some(&input), &[A, barrier, B], &[B, barrier, A]).passed(),
            "crossed {barrier}"
        );
    }
    assert!(
        !checked(
            Some(&input),
            &[r#"461-/n,936[{"_placeholder":true,"num":0}]"#, B],
            &[B, r#"461-/n,936[{"_placeholder":true,"num":0}]"#]
        )
        .passed()
    );
}

#[test]
fn paired_ack_arguments_still_evaluate_global_field_contracts() {
    let policy = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v2\njson:\n  fields:\n    /id: {kind: identity, formats: [decimal]}\n",
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
            &Default::default(),
            Some(&context),
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
    std::fs::write(&policy, "format: traffic-policy/v2\nrules: []\n").unwrap();
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
