//! Recognize a recorded Engine.IO heartbeat timeout candidate from wire evidence.
use std::collections::BTreeSet;

mod passive;
pub(crate) use passive::{Passive, event_fingerprint};

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
    pub eof_ms: u64,
    pub acknowledged: BTreeSet<u64>,
    pub pending_without_ack: BTreeSet<u64>,
}

pub(crate) fn recognize(input: &InputTranscript, output: &OutputObservation) -> Option<Evidence> {
    let eof_ms = timeout(input, output)?;
    let limit = input.policy.max_message_bytes;
    let mut decoder = SocketIoDecoder::new(limit);
    let mut actions = input.actions.iter().peekable();
    let mut receipts = Receipts::default();
    for event in &output.events {
        while let Some(action) = actions.next_if(|action| action.offset_ms < event.offset_ms) {
            let InputActionKind::Message { message } = &action.action else {
                return None;
            };
            receipts.sent(action.sequence, message, limit).ok()?;
        }
        for packet in decoder.push(&event.message).ok()? {
            match packet {
                EngineIoPacket::Ping(payload) if payload.is_empty() => {}
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
    let mut pending_without_ack = BTreeSet::new();
    for &id in &output.end.pending {
        if receipts.acknowledged.contains(&id) {
            continue;
        }
        // A recorded one-way event has no native receipt to wait for. Its
        // observable work is instead checked by the full EOF dependency prefix.
        let index = input
            .actions
            .binary_search_by_key(&id, |action| action.sequence)
            .ok()?;
        let InputActionKind::Message { message } = &input.actions[index].action else {
            return None;
        };
        if message.kind != MessageKind::Text
            || !matches!(decode_engine_io_text(&message.data, limit).ok()?,
                EngineIoPacket::Message(packet)
                    if matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent)
                        && packet.id.is_none())
        {
            return None;
        }
        pending_without_ack.insert(id);
    }
    Some(Evidence {
        eof_ms,
        acknowledged: receipts.acknowledged,
        pending_without_ack,
    })
}

fn is_ping(event: &crate::interaction::model::OutputEvent) -> bool {
    event.heartbeat && event.message.kind == MessageKind::Text && event.message.data == "2"
}

/// Identify the terminal timeout independently from proof of completed business work.
fn timeout(input: &InputTranscript, output: &OutputObservation) -> Option<u64> {
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
    let pings = output.events.iter().filter(|event| is_ping(event));
    let ping_count = pings.clone().count() as u64;
    let last = pings.last()?;
    let limit = input.policy.max_message_bytes;
    let first = output.events.first()?;
    let EngineIoPacket::Open(open) = decode_engine_io_text(&first.message.data, limit).ok()? else {
        return None;
    };
    let eof_ms = output.end.offset_ms;
    if first.message.kind != MessageKind::Text
        || eof_ms.checked_sub(last.offset_ms)? <= open.ping_timeout
        || program
            .responses
            .iter()
            .any(|response| response.ping_ordinal >= ping_count)
    {
        return None;
    }

    for action in &input.actions {
        if action.offset_ms >= eof_ms || super::timing::cancellation(action) {
            return None;
        }
        let InputActionKind::Message { message } = &action.action else {
            return None;
        };
        // Earlier unmatched PONGs cannot answer the last PING. Same-tick
        // ordering and a later PONG both leave that PING's outcome uncertain.
        if action.offset_ms >= last.offset_ms
            && message.kind == MessageKind::Text
            && matches!(
                decode_engine_io_text(&message.data, limit).ok()?,
                EngineIoPacket::Pong(_)
            )
        {
            return None;
        }
    }

    Some(eof_ms)
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
        assert_eq!(proof.eof_ms, 71);
        assert_eq!(proof.acknowledged, [request.sequence].into());
        assert_eq!(output.end.pending, vec![request.sequence]);

        let mut at_timeout = output.clone();
        at_timeout.end.offset_ms = 70;
        assert!(recognize(&input, &at_timeout).is_none());
        let mut no_ack = output.clone();
        no_ack.events.remove(2);
        assert_eq!(timeout(&input, &no_ack), Some(71));
        assert!(recognize(&input, &no_ack).is_none());
        source.input(WireMessage::text("3"), 51).unwrap();
        let (answered, output) = source.finish(EndReason::ServerEof, 71, true).unwrap();
        assert!(recognize(&answered, &output).is_none());
    }

    #[test]
    fn uses_last_unanswered_ping_for_timeout_and_eof_for_the_business_boundary() {
        let mut source =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        source
            .output(
                WireMessage::text(r#"0{"sid":"source","pingInterval":25,"pingTimeout":20}"#),
                0,
            )
            .unwrap();
        source.input(WireMessage::text("3"), 1).unwrap();
        source.input(WireMessage::text("40"), 2).unwrap();
        source
            .output(WireMessage::text(r#"40{"sid":"namespace"}"#), 3)
            .unwrap();
        source.output(WireMessage::text("2"), 25).unwrap();
        source.output(WireMessage::text("2"), 29).unwrap();
        let work = source
            .input(WireMessage::text(r#"427["work"]"#), 30)
            .unwrap();
        source
            .output(WireMessage::text(r#"437[true]"#), 31)
            .unwrap();
        let one_way = source
            .input(WireMessage::text(r#"42["one-way"]"#), 32)
            .unwrap();
        source.server_close(Some(1000), String::new());
        let (input, output) = source.finish(EndReason::ServerEof, 51, true).unwrap();
        let proof = recognize(&input, &output).unwrap();
        assert_eq!(proof.eof_ms, 51);
        assert_eq!(proof.acknowledged, [work.sequence].into());
        assert_eq!(proof.pending_without_ack, [one_way.sequence].into());

        source.input(WireMessage::text("3"), 33).unwrap();
        let (ambiguous, output) = source.finish(EndReason::ServerEof, 51, true).unwrap();
        assert!(timeout(&ambiguous, &output).is_none());
    }
}
