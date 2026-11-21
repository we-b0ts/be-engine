//! Typed transport ends are real inputs, never inferred successful EOFs.
use super::*;
use crate::interaction::{
    model::{EndReason, WireMessage},
    policy::InteractionPolicy,
};

#[test]
fn typed_eof_and_reset_preserve_pending_work_and_do_not_invent_a_close() {
    for end in [ClientTransportEnd::Eof, ClientTransportEnd::Reset] {
        let mut observation =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        observation
            .output(
                WireMessage::text(
                    r#"0{"sid":"source","upgrades":[],"pingInterval":25000,"pingTimeout":20000}"#,
                ),
                1,
            )
            .unwrap();
        observation.input(WireMessage::text("40"), 2).unwrap();
        let pending = observation.pending();
        assert!(!pending.is_empty());
        observation.client_transport_end(end, 11).unwrap();
        let (input, output) = observation
            .finish(EndReason::ClientTransportEnd, 20, true)
            .unwrap();
        assert_eq!(
            input.actions.last().unwrap().action,
            InputActionKind::TransportEnd { end }
        );
        assert_eq!(input.actions.last().unwrap().offset_ms, 11);
        assert_eq!(
            input.socket_io_heartbeat.as_ref().unwrap().responses,
            vec![]
        );
        assert_eq!(output.end.pending, pending);
        assert!(output.end.clean);
        assert!(output.end.close.is_none());
        assert!(
            !input
                .actions
                .iter()
                .any(|action| matches!(action.action, InputActionKind::Close { .. }))
        );
        assert!(
            !observation
                .finish(EndReason::ClientTransportEnd, 20, false)
                .unwrap()
                .1
                .end
                .clean
        );
    }
}

#[test]
fn ordinary_transport_errors_and_missing_terminal_inputs_do_not_become_clean() {
    let observed = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    assert!(
        observed
            .finish(EndReason::ClientTransportEnd, 10, true)
            .is_err()
    );
    for reason in [
        EndReason::TransportError,
        EndReason::RequestTimeout,
        EndReason::ServerEof,
    ] {
        assert!(!observed.finish(reason, 10, true).unwrap().1.end.clean);
    }
    let mut observed = observed;
    observed
        .client_transport_end(ClientTransportEnd::Eof, 10)
        .unwrap();
    assert!(
        !observed
            .finish(EndReason::TransportError, 11, true)
            .unwrap()
            .1
            .end
            .clean
    );
    assert!(
        !observed
            .finish(EndReason::BusinessIdle, 11, true)
            .unwrap()
            .1
            .end
            .clean
    );
}

#[test]
fn client_termination_rejects_unfinished_socket_io_binary_messages() {
    for from_client in [false, true] {
        let mut observed =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        let partial = WireMessage::text(r#"451-["attachment",{"_placeholder":true,"num":0}]"#);
        if from_client {
            observed.input(partial, 1).unwrap();
        } else {
            observed.output(partial, 1).unwrap();
        }
        assert!(
            observed
                .client_transport_end(ClientTransportEnd::Reset, 2)
                .is_err()
        );
    }
}

#[test]
fn terminal_input_ends_future_client_actions_but_allows_real_server_cleanup_observations() {
    let mut observed = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    observed
        .client_transport_end(ClientTransportEnd::Eof, 2)
        .unwrap();
    assert!(observed.input(WireMessage::text("40"), 3).is_err());
    assert!(
        observed
            .upgrade(
                "/socket.io/?transport=websocket".into(),
                Default::default(),
                3
            )
            .is_err()
    );
    assert!(observed.client_close(None, String::new(), 3).is_err());
    assert!(
        observed
            .client_transport_end(ClientTransportEnd::Reset, 3)
            .is_err()
    );
    observed
        .output(
            WireMessage::text(
                r#"0{"sid":"source","upgrades":[],"pingInterval":25000,"pingTimeout":20000}"#,
            ),
            4,
        )
        .unwrap();
    assert!(
        observed
            .finish(EndReason::ClientTransportEnd, 5, true)
            .unwrap()
            .1
            .end
            .clean
    );
}

#[test]
fn complete_websocket_messages_can_be_cancelled_without_business_completion() {
    let mut observed = Observation::new(
        Protocol::WebSocket,
        InteractionPolicy {
            stream_terminal: Some(crate::interaction::policy::StreamTerminal::Text {
                value: "done".into(),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    observed.input(WireMessage::text("request"), 1).unwrap();
    observed
        .client_transport_end(ClientTransportEnd::Reset, 2)
        .unwrap();
    let (input, output) = observed
        .finish(EndReason::ClientTransportEnd, 3, true)
        .unwrap();
    assert_eq!(output.end.pending, vec![1]);
    assert!(output.end.clean);
    assert!(input.socket_io_heartbeat.is_none());
}

#[test]
fn input_validation_rejects_nonterminal_or_correlated_transport_end_and_stream_protocols() {
    let mut observed = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    observed.input(WireMessage::text("40"), 1).unwrap();
    observed
        .client_transport_end(ClientTransportEnd::Eof, 2)
        .unwrap();
    let (input, _) = observed
        .finish(EndReason::ClientTransportEnd, 3, true)
        .unwrap();
    input.validate().unwrap();
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(
        json["actions"][1]["action"],
        serde_json::json!({"kind":"transport_end","end":"eof"})
    );
    assert_eq!(
        serde_json::from_value::<crate::interaction::model::InputTranscript>(json).unwrap(),
        input
    );
    for protocol in [Protocol::Sse, Protocol::Ndjson, Protocol::RawStream] {
        let mut invalid = input.clone();
        invalid.protocol = protocol;
        assert!(invalid.validate().is_err());
        let mut stream = Observation::new(protocol, InteractionPolicy::default()).unwrap();
        assert!(
            stream
                .client_transport_end(ClientTransportEnd::Eof, 2)
                .is_err()
        );
    }
    let mut invalid = input.clone();
    invalid.socket_io_heartbeat = None;
    assert!(invalid.validate().is_err());
    for field in 0..4 {
        let mut invalid = input.clone();
        let terminal = invalid.actions.last_mut().unwrap();
        match field {
            0 => terminal.after.push(1),
            1 => {
                terminal.ack_ref = Some(crate::interaction::model::AckReference {
                    namespace: "/".into(),
                    server_event_ordinal: 1,
                })
            }
            2 => terminal.gap_start_ms = Some(1),
            _ => {
                terminal.after.push(1);
                terminal.gap_start_ms = Some(1);
                terminal.compressible_gap = true;
            }
        }
        assert!(invalid.validate().is_err());
    }
    let mut invalid = input;
    let mut extra = invalid.actions[0].clone();
    extra.sequence = 3;
    extra.offset_ms = 3;
    invalid.actions.push(extra);
    assert!(invalid.validate().is_err());
}

#[test]
fn typed_end_retains_only_actual_client_heartbeat_responses() {
    let mut observed = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    observed.output(WireMessage::text("2first"), 2).unwrap();
    observed.input(WireMessage::text("3first"), 5).unwrap();
    observed
        .output(WireMessage::text("2unanswered"), 6)
        .unwrap();
    observed
        .client_transport_end(ClientTransportEnd::Eof, 7)
        .unwrap();
    let (input, _) = observed
        .finish(EndReason::ClientTransportEnd, 8, true)
        .unwrap();
    assert_eq!(
        input.socket_io_heartbeat.unwrap().responses,
        vec![crate::interaction::model::HeartbeatResponse {
            input_sequence: 1,
            ping_ordinal: 1,
            delay_ms: 3
        }]
    );
}
