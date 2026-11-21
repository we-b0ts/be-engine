//! Client heartbeat causality, without expected output or transport ownership.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, ensure};

use super::{
    model::{
        HeartbeatResponse, InputActionKind, InputTranscript, MessageKind, Protocol,
        SocketIoHeartbeats,
    },
    socketio::{EngineIoPacket, decode_engine_io_text},
};

#[derive(Default)]
pub(super) struct RecordedHeartbeats {
    next_ping: u64,
    pending: BTreeMap<String, VecDeque<(u64, u64)>>,
    responses: Vec<HeartbeatResponse>,
}

impl RecordedHeartbeats {
    pub(super) fn ping(&mut self, payload: String, now_ms: u64) {
        self.next_ping += 1;
        self.pending
            .entry(payload)
            .or_default()
            .push_back((self.next_ping, now_ms));
    }

    pub(super) fn pong(&mut self, payload: &str, sequence: u64, now_ms: u64) {
        if let Some(queued) = self.pending.get_mut(payload) {
            let (ordinal, at) = queued.pop_front().unwrap();
            if queued.is_empty() {
                self.pending.remove(payload);
            }
            self.responses.push(HeartbeatResponse {
                input_sequence: sequence,
                ping_ordinal: ordinal,
                delay_ms: now_ms.saturating_sub(at),
            });
        }
    }

    pub(super) fn program(&self) -> SocketIoHeartbeats {
        SocketIoHeartbeats {
            responses: self.responses.clone(),
        }
    }
}

pub(super) fn validate(input: &InputTranscript) -> Result<()> {
    let Some(program) = &input.socket_io_heartbeat else {
        return Ok(());
    };
    ensure!(
        input.protocol == Protocol::SocketIo,
        "recorded Engine.IO heartbeat behavior requires Socket.IO"
    );
    let actions: BTreeMap<_, _> = input
        .actions
        .iter()
        .map(|action| (action.sequence, action))
        .collect();
    let mut inputs = BTreeSet::new();
    let mut pings = BTreeSet::new();
    for response in &program.responses {
        ensure!(
            inputs.insert(response.input_sequence),
            "duplicate recorded heartbeat input binding"
        );
        ensure!(
            response.ping_ordinal > 0
                && response.ping_ordinal <= input.policy.max_messages as u64
                && pings.insert(response.ping_ordinal),
            "invalid or duplicate recorded heartbeat PING ordinal"
        );
        let action = actions
            .get(&response.input_sequence)
            .ok_or_else(|| anyhow::anyhow!("recorded heartbeat binding has no input action"))?;
        ensure!(
            response.delay_ms <= action.offset_ms
                && response.delay_ms
                    <= input
                        .policy
                        .request_timeout_ms
                        .min(input.policy.max_duration_ms),
            "recorded heartbeat response exceeds its time budget"
        );
        ensure!(
            action.after.is_empty() && !action.compressible_gap && action.ack_ref.is_none(),
            "recorded heartbeat cannot depend on a business completion or server ACK"
        );
        ensure!(
            matches!(&action.action, InputActionKind::Message { message } if message.kind == MessageKind::Text && matches!(decode_engine_io_text(&message.data, input.policy.max_message_bytes)?, EngineIoPacket::Pong(_))),
            "recorded heartbeat binding must reference an Engine.IO PONG input"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
