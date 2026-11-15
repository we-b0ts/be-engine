use super::super::policy::{CorrelationRule, EventCompletion};
use super::*;

fn packet(text: &str) -> SocketIoPacket {
    decode_socket_io(text, 4096).unwrap()
}

#[test]
fn eio4_polling_direct_websocket_and_upgrade_are_distinguished_without_hardcoded_path() {
    assert_eq!(
        classify_request("GET", "/custom?EIO=4&transport=polling", false)
            .unwrap()
            .transport,
        Transport::Polling
    );
    assert_eq!(
        classify_request("GET", "/custom?EIO=4&transport=websocket&sid=abc", true)
            .unwrap()
            .sid
            .as_deref(),
        Some("abc")
    );
    assert!(classify_request("GET", "/custom?EIO=3&transport=websocket", true).is_err());
    assert!(classify_request("POST", "/custom?EIO=4&transport=polling", false).is_err());
}

#[test]
fn malformed_duplicate_json_and_non_ascii_packet_types_fail_without_panicking() {
    assert!(decode_engine_io_text("42[\"ask\",{\"id\":1,\"id\":2}]", 4096).is_err());
    assert!(
        decode_engine_io_text(
            "0{\"sid\":\"first\",\"sid\":\"last\",\"pingInterval\":25,\"pingTimeout\":20}",
            4096
        )
        .is_err()
    );
    assert!(decode_engine_io_text("你", 4096).is_err());
    assert!(decode_socket_io("你", 4096).is_err());
    assert!(
        decode_engine_io_text("451-[\"upload\",{\"_placeholder\":true,\"num\":2}]", 4096).is_err()
    );
}

#[test]
fn binary_packets_are_reconstructed_and_missing_attachments_fail() {
    let mut decoder = SocketIoDecoder::new(4096);
    assert!(
        decoder
            .push(&WireMessage::text(
                "451-/chat,12[\"upload\",{\"_placeholder\":true,\"num\":0}]"
            ))
            .unwrap()
            .is_empty()
    );
    assert!(decoder.finish().is_err());
    let decoded = decoder.push(&WireMessage::binary(&[0, 255, 12])).unwrap();
    let EngineIoPacket::Message(packet) = &decoded[0] else {
        panic!()
    };
    assert_eq!(packet.id, Some(12));
    assert_eq!(
        STANDARD.decode(&packet.binary[0]).unwrap(),
        vec![0, 255, 12]
    );
    decoder.finish().unwrap();
}

#[test]
fn early_ack_does_not_finish_a_profiled_stream_and_overlaps_correlate() {
    let policy = InteractionPolicy {
        completion: vec![EventCompletion {
            namespace: "/chat".into(),
            event: "send".into(),
            completion: CompletionRule::TerminalEvent {
                event: "done".into(),
                correlation: Some(CorrelationRule {
                    input_pointer: "/0/task_id".into(),
                    output_pointer: "/0/task_id".into(),
                }),
                require_ack: true,
            },
        }],
        ..Default::default()
    };
    let mut tracker = CompletionTracker::new(policy);
    tracker
        .observe_client(1, &packet("2/chat,11[\"send\",{\"task_id\":1}]"), 0)
        .unwrap();
    tracker
        .observe_client(2, &packet("2/chat,12[\"send\",{\"task_id\":2}]"), 0)
        .unwrap();
    assert!(
        tracker
            .observe_server(&packet("3/chat,11[]"), 1)
            .unwrap()
            .completed
            .is_empty()
    );
    assert_eq!(
        tracker
            .observe_server(&packet("2/chat,[\"done\",{\"task_id\":1}]"), 2)
            .unwrap()
            .completed,
        vec![1]
    );
    assert_eq!(tracker.pending(), vec![2]);
}

#[test]
fn unprofiled_ack_is_not_silently_business_completion_and_server_rpcs_remain_pending() {
    let mut tracker = CompletionTracker::new(InteractionPolicy::default());
    tracker
        .observe_client(2, &packet("25[\"unknown\"]"), 0)
        .unwrap();
    assert!(
        tracker
            .observe_server(&packet("35[]"), 1)
            .unwrap()
            .completed
            .is_empty()
    );
    let update = tracker
        .observe_server(&packet("29[\"question\"]"), 2)
        .unwrap();
    assert_eq!(update.started.len(), 1);
    assert_eq!(
        tracker
            .observe_client(3, &packet("39[true]"), 3)
            .unwrap()
            .completed,
        update.started
    );
    assert_eq!(tracker.pending(), vec![2]);
}

#[test]
fn acknowledged_ids_can_be_reused_without_completing_unprofiled_business() {
    let mut tracker = CompletionTracker::new(InteractionPolicy::default());
    tracker
        .observe_client(1, &packet("2/chat,39[\"first\"]"), 0)
        .unwrap();
    tracker
        .observe_server(&packet("3/chat,39[true]"), 1)
        .unwrap();
    let update = tracker
        .observe_client(2, &packet("2/chat,39[\"second\"]"), 30_000)
        .unwrap();
    assert_eq!(update.started, vec![2]);
    assert_eq!(tracker.pending(), vec![1, 2]);
    tracker
        .observe_server(&packet("3/chat,39[true]"), 30_001)
        .unwrap();
    assert!(tracker.pending[&1].acked);
    assert!(tracker.pending[&2].acked);
    assert_eq!(tracker.pending(), vec![1, 2]);
}

#[test]
fn an_ack_identity_still_in_flight_cannot_be_reused() {
    let mut tracker = CompletionTracker::new(InteractionPolicy::default());
    tracker
        .observe_client(1, &packet("2/chat,39[\"first\"]"), 0)
        .unwrap();
    let error = tracker
        .observe_client(2, &packet("2/chat,39[\"second\"]"), 1)
        .unwrap_err();
    assert!(error.to_string().contains("overlapping Socket.IO ACK"));
    assert_eq!(tracker.pending(), vec![1]);
}

#[test]
fn reused_ack_ids_keep_terminal_completion_bound_to_each_request() {
    let policy = InteractionPolicy {
        completion: vec![EventCompletion {
            namespace: "/chat".into(),
            event: "send".into(),
            completion: CompletionRule::TerminalEvent {
                event: "done".into(),
                correlation: Some(CorrelationRule {
                    input_pointer: "/0/task_id".into(),
                    output_pointer: "/0/task_id".into(),
                }),
                require_ack: true,
            },
        }],
        ..Default::default()
    };
    let mut tracker = CompletionTracker::new(policy);
    tracker
        .observe_client(1, &packet("2/chat,39[\"send\",{\"task_id\":1}]"), 0)
        .unwrap();
    tracker
        .observe_server(&packet("3/chat,39[true]"), 1)
        .unwrap();
    tracker
        .observe_client(2, &packet("2/chat,39[\"send\",{\"task_id\":2}]"), 2)
        .unwrap();
    tracker
        .observe_server(&packet("3/chat,39[true]"), 3)
        .unwrap();
    assert_eq!(
        tracker
            .observe_server(&packet("2/chat,[\"done\",{\"task_id\":2}]"), 4)
            .unwrap()
            .completed,
        vec![2]
    );
    assert_eq!(tracker.pending(), vec![1]);
    assert_eq!(
        tracker
            .observe_server(&packet("2/chat,[\"done\",{\"task_id\":1}]"), 5)
            .unwrap()
            .completed,
        vec![1]
    );
}
