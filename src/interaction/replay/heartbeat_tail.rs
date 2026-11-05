//! Recognize a recorded Engine.IO heartbeat timeout candidate from wire evidence.
use std::collections::BTreeSet;

use crate::interaction::{
    model::{
        EndReason, InputActionKind, InputTranscript, MessageKind, OutputObservation, Protocol,
    },
    socketio::{
        EngineIoPacket, SocketIoDecoder, SocketIoKind, decode_engine_io_text,
        native_receipts::Receipts,
    },
};

pub(crate) struct Evidence {
    pub last_ping_ms: u64,
    pub acknowledged: BTreeSet<u64>,
}

pub(crate) fn recognize(input: &InputTranscript, output: &OutputObservation) -> Option<Evidence> {
    if input.protocol != Protocol::SocketIo
        || input.policy.preserve_input_timing
        || output.protocol != Protocol::SocketIo
        || output.end.reason != EndReason::ServerEof
        || !output.end.clean
        || output.end.partial_message.is_some()
        || !output
            .end
            .close
            .as_ref()
            .is_some_and(|close| close.code == Some(1000) && close.reason.is_empty())
    {
        return None;
    }
    let program = input.socket_io_heartbeat.as_ref()?;
    let last = output.events.last()?;
    let limit = input.policy.max_message_bytes;
    let first = output.events.first()?;
    let EngineIoPacket::Open(open) = decode_engine_io_text(&first.message.data, limit).ok()? else {
        return None;
    };
    if first.message.kind != MessageKind::Text
        || !last.heartbeat
        || last.message != crate::interaction::model::WireMessage::text("2")
        || output.end.offset_ms.checked_sub(last.offset_ms)? <= open.ping_timeout
    {
        return None;
    }

    let bound_inputs: BTreeSet<_> = program
        .responses
        .iter()
        .map(|response| response.input_sequence)
        .collect();
    for action in &input.actions {
        if action.offset_ms >= last.offset_ms || super::timing::cancellation(action) {
            return None;
        }
        let InputActionKind::Message { message } = &action.action else {
            return None;
        };
        if message.kind == MessageKind::Text
            && matches!(
                decode_engine_io_text(&message.data, limit).ok()?,
                EngineIoPacket::Pong(_)
            )
            && !bound_inputs.contains(&action.sequence)
        {
            return None;
        }
    }

    let mut decoder = SocketIoDecoder::new(limit);
    let mut actions = input.actions.iter().peekable();
    let mut receipts = Receipts::default();
    let mut ping_count = 0;
    for event in &output.events {
        while let Some(action) = actions.next_if(|action| action.offset_ms < event.offset_ms) {
            let InputActionKind::Message { message } = &action.action else {
                return None;
            };
            receipts.sent(action.sequence, message, limit).ok()?;
        }
        for packet in decoder.push(&event.message).ok()? {
            match packet {
                EngineIoPacket::Ping(payload) if payload.is_empty() => ping_count += 1,
                EngineIoPacket::Ping(_) | EngineIoPacket::Close => return None,
                EngineIoPacket::Message(packet)
                    if matches!(packet.kind, SocketIoKind::Ack | SocketIoKind::BinaryAck) =>
                {
                    receipts.acknowledge(&packet)?;
                }
                _ => {}
            }
        }
    }
    decoder.finish().ok()?;
    if program.responses.len() + 1 != ping_count
        || program
            .responses
            .iter()
            .any(|response| response.ping_ordinal >= ping_count as u64)
        || !output
            .end
            .pending
            .iter()
            .all(|id| receipts.acknowledged.contains(id))
    {
        return None;
    }
    Some(Evidence {
        last_ping_ms: last.offset_ms,
        acknowledged: receipts.acknowledged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::{
        model::WireMessage, observation::Observation, policy::InteractionPolicy,
    };

    #[test]
    fn requires_unanswered_terminal_ping_and_recorded_ack_for_pending_work() {
        let mut source =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        source
            .output(
                WireMessage::text(r#"0{"sid":"source","pingInterval":25,"pingTimeout":20}"#),
                0,
            )
            .unwrap();
        source.input(WireMessage::text("40"), 1).unwrap();
        source
            .output(WireMessage::text(r#"40{"sid":"namespace"}"#), 2)
            .unwrap();
        let request = source
            .input(WireMessage::text(r#"427["work"]"#), 3)
            .unwrap();
        source.output(WireMessage::text(r#"437[true]"#), 4).unwrap();
        source.output(WireMessage::text("2"), 25).unwrap();
        source.input(WireMessage::text("3"), 26).unwrap();
        source.output(WireMessage::text("2"), 50).unwrap();
        source.server_close(Some(1000), String::new());
        let (input, output) = source.finish(EndReason::ServerEof, 71, true).unwrap();
        let proof = recognize(&input, &output).unwrap();
        assert_eq!(proof.last_ping_ms, 50);
        assert_eq!(proof.acknowledged, [request.sequence].into());
        assert_eq!(output.end.pending, vec![request.sequence]);

        let mut at_timeout = output.clone();
        at_timeout.end.offset_ms = 70;
        assert!(recognize(&input, &at_timeout).is_none());
        let mut no_ack = output.clone();
        no_ack.events.remove(2);
        assert!(recognize(&input, &no_ack).is_none());
        source.input(WireMessage::text("3"), 51).unwrap();
        let (answered, output) = source.finish(EndReason::ServerEof, 71, true).unwrap();
        assert!(recognize(&answered, &output).is_none());
    }
}
