//! Live namespace admission is a protocol barrier, independent of input offsets.
use std::collections::BTreeSet;

use anyhow::Result;

use crate::interaction::{
    model::{InputAction, InputActionKind, MessageKind, WireMessage},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};

#[derive(Default)]
pub(super) struct Admission {
    pending: BTreeSet<String>,
}

impl Admission {
    pub(super) fn permits(&self, action: &InputAction, limit: usize) -> bool {
        let InputActionKind::Message { message } = &action.action else {
            return true;
        };
        if message.kind != MessageKind::Text {
            return true;
        }
        // Malformed inputs retain their ordinary validation error at send time.
        let Ok(EngineIoPacket::Message(packet)) = decode_engine_io_text(&message.data, limit)
        else {
            return true;
        };
        // ACKs already require their actual Target server-event binding. Keep
        // those replies available if the peer emits during namespace setup.
        !matches!(packet.kind, SocketIoKind::Event | SocketIoKind::BinaryEvent)
            || !self.pending.contains(&packet.namespace)
    }

    pub(super) fn sent(&mut self, message: &WireMessage, limit: usize) -> Result<()> {
        if message.kind == MessageKind::Text
            && let EngineIoPacket::Message(packet) = decode_engine_io_text(&message.data, limit)?
        {
            match packet.kind {
                SocketIoKind::Connect => {
                    self.pending.insert(packet.namespace);
                }
                SocketIoKind::Disconnect => {
                    self.pending.remove(&packet.namespace);
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) fn accept(&mut self, namespace: &str) {
        self.pending.remove(namespace);
    }
}
