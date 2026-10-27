use super::*;
use crate::interaction::model::HeartbeatResponse;

fn pending_socket() -> Observation {
    let mut observed = Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
    observed
        .output(
            WireMessage::text(
                r#"0{"sid":"source","upgrades":[],"pingInterval":25000,"pingTimeout":20000}"#,
            ),
            1,
        )
        .unwrap();
    observed.input(WireMessage::text("40"), 2).unwrap();
    observed
        .output(WireMessage::text(r#"40{"sid":"namespace"}"#), 3)
        .unwrap();
    observed
        .input(WireMessage::text(r#"421["request"]"#), 4)
        .unwrap();
    observed
}

#[test]
fn explicit_source_close_keeps_pending_and_records_client_heartbeat_causality() {
    let mut observed = pending_socket();
    observed
        .output(WireMessage::text("2source-ping"), 10)
        .unwrap();
    observed
        .input(WireMessage::text("3source-ping"), 17)
        .unwrap();
    observed
        .output(WireMessage::text("2unanswered"), 30)
        .unwrap();
    observed.server_close(Some(1000), String::new());
    let (input, output) = observed.finish(EndReason::ServerEof, 50, true).unwrap();
    assert!(output.end.clean);
    assert_eq!(output.end.pending, vec![2]);
    assert_eq!(output.end.close.unwrap().code, Some(1000));
    let program = input.socket_io_heartbeat.as_ref().unwrap();
    assert_eq!(
        program.responses,
        vec![HeartbeatResponse {
            input_sequence: 3,
            ping_ordinal: 1,
            delay_ms: 7
        }]
    );
    input.validate().unwrap();
    assert_eq!(
        serde_json::from_value::<InputTranscript>(serde_json::to_value(&input).unwrap()).unwrap(),
        input
    );
}

#[test]
fn empty_source_close_program_differs_from_legacy_automatic_heartbeats() {
    let mut observed = pending_socket();
    observed.server_close(Some(1000), String::new());
    let (input, output) = observed.finish(EndReason::ServerEof, 50, true).unwrap();
    assert!(output.end.clean);
    assert!(input.socket_io_heartbeat.unwrap().responses.is_empty());
    let (legacy, output) = pending_socket()
        .finish(EndReason::ServerEof, 50, true)
        .unwrap();
    assert!(!output.end.clean);
    assert!(legacy.socket_io_heartbeat.is_none());
    let legacy_json = serde_json::to_value(&legacy).unwrap();
    assert!(legacy_json.get("socket_io_heartbeat").is_none());
    serde_json::from_value::<InputTranscript>(legacy_json)
        .unwrap()
        .validate()
        .unwrap();
}

#[test]
fn peer_close_does_not_certify_corrupt_transport_or_unfinished_binary_attachments() {
    let mut observed = pending_socket();
    observed.server_close(Some(1000), String::new());
    assert!(
        !observed
            .finish(EndReason::ServerEof, 50, false)
            .unwrap()
            .1
            .end
            .clean
    );
    assert!(
        !observed
            .finish(EndReason::TransportError, 50, true)
            .unwrap()
            .1
            .end
            .clean
    );
    assert!(
        !observed
            .finish(EndReason::RequestTimeout, 50, true)
            .unwrap()
            .1
            .end
            .clean
    );
    observed
        .output(
            WireMessage::text(r#"451-["attachment",{"_placeholder":true,"num":0}]"#),
            40,
        )
        .unwrap();
    assert!(observed.finish(EndReason::ServerEof, 50, true).is_err());
}

#[test]
fn generic_websocket_source_close_is_a_complete_session_without_fabricating_business_completion() {
    let mut observed = Observation::new(
        Protocol::WebSocket,
        InteractionPolicy {
            stream_terminal: Some(super::super::policy::StreamTerminal::Text {
                value: "done".into(),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    observed.input(WireMessage::text("request"), 1).unwrap();
    observed.server_close(Some(1000), String::new());
    let (input, output) = observed.finish(EndReason::ServerEof, 2, true).unwrap();
    assert!(output.end.clean);
    assert_eq!(output.end.pending, vec![1]);
    assert!(input.socket_io_heartbeat.is_none());
}

#[test]
fn engine_io_protocol_close_ends_a_session_without_inventing_a_websocket_close_frame() {
    let mut observed = pending_socket();
    observed.output(WireMessage::text("1"), 40).unwrap();
    let (input, output) = observed.finish(EndReason::ServerEof, 50, true).unwrap();
    assert!(output.end.clean);
    assert_eq!(output.end.pending, vec![2]);
    assert!(output.end.close.is_none());
    assert!(input.socket_io_heartbeat.unwrap().responses.is_empty());
    assert!(
        !observed
            .finish(EndReason::TransportError, 50, true)
            .unwrap()
            .1
            .end
            .clean
    );
}
