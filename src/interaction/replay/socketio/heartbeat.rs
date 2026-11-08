//! Engine.IO replies are anchored only to actual Target PING packets.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use tokio::time::{Duration, Instant};

use crate::interaction::{
    model::{InputAction, InputTranscript, MessageKind, WireMessage},
    socketio::{EngineIoPacket, decode_engine_io_text},
};

#[derive(Default)]
pub(super) struct Terminal {
    timeout: Duration,
    unanswered: Option<(Instant, String)>,
}

impl Terminal {
    pub(super) fn configure(&mut self, timeout_ms: u64) {
        self.timeout = Duration::from_millis(timeout_ms);
    }

    pub(super) fn defer_pong(&mut self, payload: String, received: Instant) {
        self.unanswered.get_or_insert((received, payload));
    }

    pub(super) fn business_output(&mut self, now: Instant) -> Option<WireMessage> {
        if self
            .unanswered
            .as_ref()
            .is_some_and(|(received, _)| now.duration_since(*received) < self.timeout)
        {
            let (_, payload) = self.unanswered.take().expect("pending terminal ping");
            return Some(WireMessage::text(format!("3{payload}")));
        }
        None
    }

    pub(super) fn expired(&self, now: Instant) -> bool {
        !self.timeout.is_zero()
            && self.unanswered.as_ref().is_some_and(|(received, _)| {
                // The server starts its deadline before the ping reaches our reader.
                let tolerance = Duration::from_millis(10).min(self.timeout / 10);
                now.duration_since(*received) >= self.timeout - tolerance
            })
    }
}

pub(super) struct Heartbeats {
    recorded: bool,
    bound_inputs: BTreeSet<u64>,
    responses: BTreeMap<u64, (u64, u64)>,
    pending: BTreeMap<(Instant, u64), (u64, String)>,
    next_ping: u64,
}

impl Heartbeats {
    pub(super) fn new(input: &InputTranscript, keep_alive: bool) -> Self {
        let recorded = input.socket_io_heartbeat.as_ref().filter(|_| !keep_alive);
        Self {
            recorded: recorded.is_some(),
            bound_inputs: recorded
                .into_iter()
                .flat_map(|program| &program.responses)
                .map(|response| response.input_sequence)
                .collect(),
            responses: recorded
                .into_iter()
                .flat_map(|program| &program.responses)
                .map(|response| {
                    (
                        response.ping_ordinal,
                        (response.input_sequence, response.delay_ms),
                    )
                })
                .collect(),
            pending: BTreeMap::new(),
            next_ping: 0,
        }
    }

    pub(super) fn recorded_pong(&self, message: &WireMessage, limit: usize) -> Result<bool> {
        Ok(self.recorded
            && message.kind == MessageKind::Text
            && matches!(
                decode_engine_io_text(&message.data, limit)?,
                EngineIoPacket::Pong(_)
            ))
    }

    pub(super) fn literal_pong(
        &self,
        action: &InputAction,
        message: &WireMessage,
        limit: usize,
    ) -> Result<bool> {
        Ok(self.recorded_pong(message, limit)? && !self.bound_inputs.contains(&action.sequence))
    }

    /// Returns true when the replay client must send an immediate PONG.
    pub(super) fn ping(&mut self, payload: String, now: Instant) -> Result<bool> {
        self.next_ping += 1;
        if let Some((sequence, delay)) = self.responses.remove(&self.next_ping) {
            let due = now
                .checked_add(Duration::from_millis(delay))
                .context("recorded heartbeat delay exceeds the Target clock range")?;
            self.pending
                .insert((due, self.next_ping), (sequence, payload));
        }
        Ok(!self.recorded)
    }

    pub(super) fn next_due(&self) -> Option<Instant> {
        self.pending.first_key_value().map(|((due, _), _)| *due)
    }

    pub(super) fn take_due(&mut self) -> WireMessage {
        let (_, (_, payload)) = self.pending.pop_first().unwrap();
        WireMessage::text(format!("3{payload}"))
    }

    pub(super) fn complete(&self, allow_unseen: bool) -> bool {
        (allow_unseen || self.responses.is_empty()) && self.pending.is_empty()
    }
}
