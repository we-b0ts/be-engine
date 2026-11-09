use super::*;
use crate::interaction::{
    model::{InputAction, WireMessage},
    policy::InteractionPolicy,
};

fn input() -> InputTranscript {
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 10,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("3source"),
        },
    });
    input.socket_io_heartbeat = Some(SocketIoHeartbeats {
        responses: vec![HeartbeatResponse {
            input_sequence: 1,
            ping_ordinal: 1,
            delay_ms: 5,
        }],
    });
    input
}

#[test]
fn heartbeat_program_rejects_non_pong_inputs_duplicate_or_missing_bindings_and_unbounded_delays() {
    let base = input();
    base.validate().unwrap();
    for (sequence, ordinal, delay) in [(2, 1, 5), (1, 0, 5), (1, 1, 11), (1, 100_001, 5)] {
        let mut bad = base.clone();
        bad.socket_io_heartbeat.as_mut().unwrap().responses[0] = HeartbeatResponse {
            input_sequence: sequence,
            ping_ordinal: ordinal,
            delay_ms: delay,
        };
        assert!(bad.validate().is_err());
    }
    let mut bad = base.clone();
    bad.actions[0].action = InputActionKind::Message {
        message: WireMessage::text("2ping"),
    };
    assert!(bad.validate().is_err());
    let mut bad = base.clone();
    let duplicate = bad.socket_io_heartbeat.as_ref().unwrap().responses[0].clone();
    bad.socket_io_heartbeat
        .as_mut()
        .unwrap()
        .responses
        .push(duplicate);
    assert!(bad.validate().is_err());
    let mut bad = base.clone();
    bad.protocol = Protocol::Sse;
    assert!(bad.validate().is_err());
    let mut bad = base;
    bad.policy.request_timeout_ms = 4;
    assert!(bad.validate().is_err());
}
