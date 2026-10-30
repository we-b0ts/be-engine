//! Native input receipts are independent of business completion and fast timing.
use crate::interaction::{
    model::{MessageKind, WireMessage},
    socketio::{EngineIoPacket, SocketIoKind, SocketIoPacket, decode_engine_io_text},
};
use anyhow::Result;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Receipts {
    sent: BTreeMap<(String, u64), Option<u64>>,
}

impl Receipts {
    pub(super) fn sent(
        &mut self,
        sequence: u64,
        message: &WireMessage,
        limit: usize,
    ) -> Result<()> {
        if message.kind != MessageKind::Text {
            return Ok(());
        }
        let EngineIoPacket::Message(packet) = decode_engine_io_text(&message.data, limit)? else {
            return Ok(());
        };
        match packet.kind {
            SocketIoKind::Event | SocketIoKind::BinaryEvent => {
                if let Some(id) = packet.id {
                    self.sent
                        .entry((packet.namespace, id))
                        .and_modify(|sequence| *sequence = None)
                        .or_insert(Some(sequence));
                }
            }
            SocketIoKind::Disconnect => self
                .sent
                .retain(|(namespace, _), _| namespace != &packet.namespace),
            _ => (),
        }
        Ok(())
    }
    pub(super) fn acknowledge(&mut self, packet: &SocketIoPacket) -> Option<u64> {
        self.sent
            .remove(&(packet.namespace.clone(), packet.id?))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_does_not_override_business_completion_policy() {
        use crate::interaction::{
            model::Protocol, observation::Observation, policy::InteractionPolicy,
        };
        let mut observed =
            Observation::new(Protocol::SocketIo, InteractionPolicy::default()).unwrap();
        observed.input(WireMessage::text("40/chat,{}"), 0).unwrap();
        observed
            .output(WireMessage::text("40/chat,{\"sid\":\"live\"}"), 1)
            .unwrap();
        let message = WireMessage::text("42/chat,7[\"work\",{}]");
        let input = observed.input(message.clone(), 2).unwrap();
        let mut receipts = Receipts::default();
        receipts.sent(input.sequence, &message, 1024).unwrap();
        let ack = WireMessage::text("43/chat,7[true]");
        observed.output(ack.clone(), 3).unwrap();
        let EngineIoPacket::Message(packet) = decode_engine_io_text(&ack.data, 1024).unwrap()
        else {
            panic!("ACK")
        };
        assert_eq!(receipts.acknowledge(&packet), Some(input.sequence));
        assert!(observed.pending().contains(&input.sequence));
        assert_eq!(receipts.acknowledge(&packet), None);
    }
}
