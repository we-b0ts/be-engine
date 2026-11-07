use super::*;
use crate::interaction::model::InputActionKind;

#[test]
fn future_recorded_input_uses_session_budget_then_restores_business_idle() {
    let started = Instant::now();
    let mut input = InputTranscript::new(
        Protocol::SocketIo,
        crate::interaction::policy::InteractionPolicy::default(),
    );
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 40_000,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("1"),
        },
    });
    let mut observed = Observation::new(input.protocol, input.policy.clone()).unwrap();
    observed
        .output(
            WireMessage::text(
                "0{\"sid\":\"live\",\"upgrades\":[],\"pingInterval\":25000,\"pingTimeout\":20000}",
            ),
            0,
        )
        .unwrap();
    assert_eq!(
        session_deadline(&input, &observed, 0, started),
        started + Duration::from_millis(input.policy.max_duration_ms)
    );
    assert_eq!(
        session_deadline(&input, &observed, 1, started),
        started + Duration::from_millis(input.policy.business_idle_ms)
    );
}

#[test]
fn input_gap_compression_waits_for_independently_observed_target_completion() {
    let sent = Instant::now();
    let action = InputAction {
        sequence: 2,
        offset_ms: 30_000,
        offset_us: None,
        after: vec![1],
        compressible_gap: true,
        gap_start_ms: Some(2_000),
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("42[\"next\"]"),
        },
    };
    let mut completed = BTreeMap::new();
    assert!(websocket_action_due(&action, &completed, 0, sent, 100).is_none());
    let target_done = sent + Duration::from_secs(2);
    completed.insert(1, target_done);
    assert_eq!(
        websocket_action_due(&action, &completed, 0, sent, 100),
        Some(target_done + Duration::from_millis(100))
    );
    let overlap = InputAction {
        after: vec![],
        compressible_gap: false,
        ..action
    };
    assert_eq!(
        websocket_action_due(&overlap, &completed, 0, sent, 100),
        Some(sent + Duration::from_secs(30))
    );
}

#[test]
fn explicit_close_preserves_the_gap_after_actual_completion() {
    let sent = Instant::now();
    let target_done = sent + Duration::from_millis(40);
    let mut completed = BTreeMap::new();
    let mut action = InputAction {
        sequence: 3,
        offset_ms: 57,
        offset_us: None,
        after: vec![2],
        compressible_gap: false,
        gap_start_ms: Some(7),
        ack_ref: None,
        action: InputActionKind::Close {
            code: None,
            reason: String::new(),
        },
    };
    assert!(websocket_action_due(&action, &completed, 10, sent, 1).is_none());
    completed.insert(2, target_done);
    assert_eq!(
        websocket_action_due(&action, &completed, 10, sent, 1),
        Some(target_done + Duration::from_millis(50))
    );
    action.action = InputActionKind::Message {
        message: WireMessage::text("1"),
    };
    assert_eq!(
        websocket_action_due(&action, &completed, 10, sent, 1),
        Some(sent + Duration::from_millis(47)),
        "a generic WebSocket text message is not an Engine.IO close"
    );
}
