//! Socket.IO business input follows the recorded prefix of server events.
use std::collections::{BTreeMap, VecDeque};

use tokio::time::{Duration, Instant};

use crate::interaction::{
    model::{InputAction, InputActionKind, MessageKind, MissingPredecessor},
    socketio::{SocketIoKind, SocketIoPacket},
};

pub(super) const WAIT: Duration = Duration::from_secs(5);
const FAST_GAP_MS: u64 = 5;

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
    arrived: Vec<Option<Instant>>,
    prefix: usize,
    compress: bool,
}

impl Order {
    pub(crate) fn new(events: Vec<(EventKey, Checkpoint)>, compress: bool) -> Self {
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
            arrived: vec![None; checkpoints.len()],
            checkpoints,
            occurrences,
            prefix: 0,
            compress,
        }
    }

    pub(super) fn observe(&mut self, packet: &SocketIoPacket, at: Instant) {
        let Some(index) = EventKey::of(packet)
            .and_then(|key| self.occurrences.get_mut(&key))
            .and_then(VecDeque::pop_front)
        else {
            return;
        };
        self.arrived[index] = Some(at);
        // A reordered arrival can satisfy its own slot but cannot fill an
        // earlier missing slot. The prefix clock is its latest live arrival.
        while let Some(Some(at)) = self.arrived.get(self.prefix).copied() {
            if self.prefix > 0 {
                self.arrived[self.prefix] = self.arrived[self.prefix - 1].map(|last| last.max(at));
            }
            self.prefix += 1;
        }
    }

    pub(super) fn schedule(
        &self,
        action: &InputAction,
        started: Instant,
        last_sent: Instant,
        last_offset: u64,
    ) -> Schedule {
        // Recorded server timestamps are floor milliseconds. An equal input
        // timestamp is ambiguous even when only the input has offset_us.
        let required = self
            .checkpoints
            .partition_point(|checkpoint| checkpoint.offset_ms < action.offset_ms);
        let recorded_due = started + Duration::from_millis(action.offset_ms);
        let expires = recorded_due + WAIT;
        // Keep the expiry authoritative even if a frame and the timer become
        // ready on the same loop turn.
        let received = self.arrived[..required.min(self.prefix)]
            .partition_point(|at| at.is_some_and(|at| at <= expires));
        if received < required {
            return Schedule::Waiting {
                expires,
                missing: MissingPredecessor {
                    input_sequence: action.sequence,
                    output_sequence: self.checkpoints[received].sequence,
                },
            };
        }
        let Some(index) = required.checked_sub(1) else {
            return Schedule::Unbound(recorded_due);
        };
        let checkpoint = &self.checkpoints[index];
        let arrival = self.arrived[index].expect("completed event prefix");
        let gap = action.offset_ms - checkpoint.offset_ms.max(last_offset);
        let due = arrival.max(last_sent)
            + Duration::from_millis(if self.compress {
                gap.min(FAST_GAP_MS)
            } else {
                gap
            });
        Schedule::Ready(if self.compress {
            due
        } else {
            due.max(recorded_due)
        })
    }
}

pub(super) enum Schedule {
    Unbound(Instant),
    Ready(Instant),
    Waiting {
        expires: Instant,
        missing: MissingPredecessor,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interaction::{
        model::{InputActionKind, WireMessage},
        socketio::{EngineIoPacket, decode_engine_io_text},
    };

    #[test]
    fn missing_prefix_expires_five_seconds_after_the_recorded_input() {
        let start = Instant::now();
        let mut order = Order::new(
            vec![
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
            ],
            true,
        );
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
        let Schedule::Waiting { expires, missing } = order.schedule(&action, start, start, 86)
        else {
            panic!("the recorded ACK must arrive first");
        };
        assert_eq!(expires, start + Duration::from_millis(5_151));
        assert_eq!(
            missing,
            MissingPredecessor {
                input_sequence: 4,
                output_sequence: 3
            }
        );
        let EngineIoPacket::Message(ack) = decode_engine_io_text("437[true]", 128).unwrap() else {
            panic!("Socket.IO ACK");
        };
        let arrival = start + Duration::from_millis(536);
        order.observe(&ack, arrival);
        let Schedule::Ready(due) = order.schedule(&action, start, start, 86) else {
            panic!("an output in the same recorded millisecond does not block");
        };
        assert_eq!(due, arrival + Duration::from_millis(5));
    }
}
