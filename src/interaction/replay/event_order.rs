//! Socket.IO business input follows the recorded prefix of server events.
use std::collections::{BTreeMap, VecDeque};

use crate::interaction::{
    model::{InputAction, InputActionKind, MessageKind, MissingPredecessor},
    socketio::{SocketIoKind, SocketIoPacket},
};

pub(super) fn attachment(action: &InputAction) -> bool {
    matches!(
        &action.action,
        InputActionKind::Message { message }
            if message.kind == MessageKind::Binary || message.data.starts_with('b')
    )
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EventKey {
    Event(String, String),
    Ack(String, u64),
}

impl EventKey {
    pub(crate) fn of(packet: &SocketIoPacket) -> Option<Self> {
        match packet.kind {
            SocketIoKind::Event | SocketIoKind::BinaryEvent => Some(Self::Event(
                packet.namespace.clone(),
                packet.event_name()?.to_owned(),
            )),
            SocketIoKind::Ack | SocketIoKind::BinaryAck => {
                Some(Self::Ack(packet.namespace.clone(), packet.id?))
            }
            _ => None,
        }
    }
}

pub(crate) struct Checkpoint {
    pub(crate) sequence: u64,
    pub(crate) offset_ms: u64,
}

pub(crate) struct Order {
    checkpoints: Vec<Checkpoint>,
    occurrences: BTreeMap<EventKey, VecDeque<usize>>,
    arrived: Vec<bool>,
    prefix: usize,
}

impl Order {
    pub(crate) fn new(events: Vec<(EventKey, Checkpoint)>) -> Self {
        let mut occurrences = BTreeMap::<_, VecDeque<_>>::new();
        let checkpoints: Vec<_> = events
            .into_iter()
            .enumerate()
            .map(|(index, (key, checkpoint))| {
                occurrences.entry(key).or_default().push_back(index);
                checkpoint
            })
            .collect();
        Self {
            arrived: vec![false; checkpoints.len()],
            checkpoints,
            occurrences,
            prefix: 0,
        }
    }

    pub(super) fn observe(&mut self, packet: &SocketIoPacket) {
        let Some(index) = EventKey::of(packet)
            .and_then(|key| self.occurrences.get_mut(&key))
            .and_then(VecDeque::pop_front)
        else {
            return;
        };
        self.arrived[index] = true;
        // Reordered arrivals can satisfy their own slots while the prefix
        // waits for an earlier missing event.
        while self.arrived.get(self.prefix) == Some(&true) {
            self.prefix += 1;
        }
    }

    pub(super) fn missing(&self, action: &InputAction) -> Option<MissingPredecessor> {
        let checkpoint = self.checkpoints.get(self.prefix)?;
        // Output timestamps are floor milliseconds. Equal timestamps cannot
        // prove that an output preceded this input, even with input offset_us.
        (checkpoint.offset_ms < action.offset_ms).then_some(MissingPredecessor {
            input_sequence: action.sequence,
            output_sequence: checkpoint.sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::{
        model::{InputActionKind, WireMessage},
        socketio::{EngineIoPacket, decode_engine_io_text},
    };

    #[test]
    fn waits_for_a_proven_prefix_and_excludes_equal_milliseconds() {
        let mut order = Order::new(vec![
            (
                EventKey::Ack("/".into(), 7),
                Checkpoint {
                    sequence: 3,
                    offset_ms: 138,
                },
            ),
            (
                EventKey::Event("/other".into(), "ready".into()),
                Checkpoint {
                    sequence: 4,
                    offset_ms: 151,
                },
            ),
        ]);
        let action = InputAction {
            sequence: 4,
            offset_ms: 151,
            offset_us: Some(151_900),
            after: Vec::new(),
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::Message {
                message: WireMessage::text(r#"42["heartbeat"]"#),
            },
        };
        assert_eq!(
            order.missing(&action),
            Some(MissingPredecessor {
                input_sequence: 4,
                output_sequence: 3
            }),
        );
        let EngineIoPacket::Message(ack) = decode_engine_io_text("437[true]", 128).unwrap() else {
            panic!("Socket.IO ACK");
        };
        order.observe(&ack);
        assert_eq!(order.missing(&action), None);
    }
}
