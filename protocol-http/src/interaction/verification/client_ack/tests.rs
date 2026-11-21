use super::*;
use crate::interaction::{
    model::{EndObservation, EndReason, InputAction, OutputEvent},
    policy::InteractionPolicy,
};

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

fn checked(input: Option<&InputTranscript>, source: &[&str], target: &[&str]) -> Comparison {
    let context = Context::prepare(input).unwrap();
    super::super::compare_outputs(
        Some(&output(source)),
        Some(&output(target)),
        None,
        &super::super::ComparisonContext {
            times: Default::default(),
            request_times: Default::default(),
            ack_context: context.as_ref(),
            source_heartbeat_tail: false,
            max_message_bytes: 8 * 1024 * 1024,
        },
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
fn pending_acks_can_cross_text_events_without_reordering_business_frames() {
    const PUSH: &str = r#"42/n,17["notice",{"seq":1}]"#;
    const LIVE_PUSH: &str = r#"42/n,99["notice",{"seq":1}]"#;
    const NEXT: &str = r#"42/n,["notice",{"seq":2}]"#;
    let input = input();
    for (source, target) in [
        (vec![PUSH, A], vec![A, LIVE_PUSH]),
        (vec![A, LIVE_PUSH], vec![PUSH, A]),
        (vec![PUSH, NEXT, A, B], vec![B, PUSH, A, NEXT]),
    ] {
        assert!(checked(Some(&input), &source, &target).passed());
    }
    let mut long_source = vec![NEXT; 130];
    long_source.extend([PUSH, A]);
    let mut long_target = vec![NEXT; 130];
    long_target.extend([A, LIVE_PUSH]);
    assert!(checked(Some(&input), &long_source, &long_target).passed());

    for target in [
        vec![A, NEXT, LIVE_PUSH],
        vec![A, LIVE_PUSH, LIVE_PUSH],
        vec![A, LIVE_PUSH],
        vec![r#"43/n,936[{"tag":"changed"}]"#, LIVE_PUSH, NEXT],
        vec![r#"43/n,811[{"tag":"A"}]"#, LIVE_PUSH, NEXT],
        vec![A, r#"42/elsewhere,17["notice",{"seq":1}]"#, NEXT],
    ] {
        assert!(
            !checked(Some(&input), &[PUSH, NEXT, A], &target).passed(),
            "{target:?}"
        );
    }
}

#[test]
fn ack_crossing_respects_request_arrival_and_recorded_input_edges() {
    const PUSH: &str = r#"42/n,["notice",{}]"#;
    let mut delayed = input();
    delayed.actions[1].offset_ms = 42_000;
    assert!(!checked(Some(&delayed), &[PUSH, B], &[B, PUSH]).passed());

    let mut dependent = input();
    let mut next = dependent.actions[0].clone();
    next.sequence = 3;
    next.offset_ms = 41_500;
    next.after = vec![1];
    next.action = InputActionKind::Message {
        message: WireMessage::text(r#"42/n,["continue",{}]"#),
    };
    dependent.actions.push(next);
    assert!(!checked(Some(&dependent), &[A, PUSH], &[PUSH, A]).passed());

    let mut fenced = input();
    let mut control = fenced.actions[1].clone();
    control.sequence = 3;
    control.offset_ms = 41_500;
    control.action = InputActionKind::Message {
        message: WireMessage::text("41/n,"),
    };
    fenced.actions.push(control);
    assert!(!checked(Some(&fenced), &[PUSH, A], &[A, PUSH]).passed());

    let mut ordered = input();
    ordered.actions[1].after = vec![1];
    assert!(!checked(Some(&ordered), &[A, PUSH, B], &[B, PUSH, A]).passed());
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
fn repeated_ack_ids_only_fence_their_own_positions() {
    const FIRST: &str = r#"43/n,215[{"tag":"first"}]"#;
    const SECOND: &str = r#"43/n,215[{"tag":"second"}]"#;
    const PUSH: &str = r#"42/n,17["notice",{}]"#;
    let mut input = input();
    let mut repeated = input.actions[0].clone();
    repeated.action = InputActionKind::Message {
        message: WireMessage::text(r#"42/n,215["poll",{}]"#),
    };
    for action in &mut input.actions {
        action.sequence += 2;
    }
    for sequence in [2, 1] {
        repeated.sequence = sequence;
        repeated.offset_ms = sequence * 1_000;
        input.actions.insert(0, repeated.clone());
    }
    let source = &[FIRST, SECOND, A, B];
    assert!(checked(Some(&input), source, &[FIRST, SECOND, B, A]).passed());
    assert!(!checked(Some(&input), source, &[SECOND, FIRST, B, A]).passed());
    assert!(!checked(Some(&input), source, &[FIRST, B, SECOND, A]).passed());

    let source = &[FIRST, PUSH, A, SECOND, B];
    assert!(checked(Some(&input), source, &[FIRST, A, PUSH, SECOND, B]).passed());
    assert!(!checked(Some(&input), source, &[FIRST, A, SECOND, PUSH, B]).passed());
    assert!(!checked(Some(&input), source, &[SECOND, A, PUSH, FIRST, B]).passed());
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
fn ack_pairing_never_crosses_other_namespaces_controls_or_binary_frames() {
    let input = input();
    for barrier in [
        r#"42/other,["notice",{}]"#,
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
