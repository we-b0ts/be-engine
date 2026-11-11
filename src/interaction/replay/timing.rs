//! Replay timing is separate from immutable recording policy and protocol completion.
use crate::interaction::{
    model::{DispatchDependency, InputAction, InputActionKind, MessageKind},
    socketio::{EngineIoPacket, SocketIoKind, decode_engine_io_text},
};
use anyhow::Result;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};

pub(crate) const SOCKET_IO_DISPATCH_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SocketIoTiming {
    #[default]
    Auto,
    Recorded,
}

/// Only the trusted input driver supplies actual completion identities. The
/// dependency replay owner supplies delivery facts and commits clock changes.
pub(crate) trait InputTiming: Send + Sync {
    fn wait(&self, sequence: u64, completed: Vec<u64>) -> BoxFuture<'_, Result<Advance>>;
    fn wait_dispatch(
        &self,
        sequence: u64,
        completed: Vec<u64>,
        mut events_ready: watch::Receiver<bool>,
        _unadmitted: watch::Sender<Option<DispatchDependency>>,
    ) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(async move {
            events_ready.wait_for(|ready| *ready).await?;
            self.wait(sequence, completed).await
        })
    }
    fn ordered_fast(&self) -> bool {
        false
    }
    fn fast_tail(&self) -> Option<FastTail> {
        None
    }
    fn wait_fast_tail(&self) -> BoxFuture<'_, Result<Advance>> {
        Box::pin(async { Ok(Advance::default()) })
    }
    fn native_prefix_active(&self) -> BoxFuture<'_, Result<bool>> {
        Box::pin(async { Ok(false) })
    }
    fn closed(&self, _started_at: chrono::DateTime<chrono::Utc>) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FastTail {
    pub close_sequence: Option<u64>,
    pub output_count: usize,
    pub idle_ms: u64,
    #[serde(default)]
    pub heartbeat_timeout: bool,
    #[serde(default)]
    pub native_observation: bool,
}

impl FastTail {
    pub(super) fn business_idle_due(
        &self,
        ready: Instant,
        last_sent: Instant,
        last_output: Instant,
    ) -> Option<Instant> {
        (self.close_sequence.is_none() && !self.heartbeat_timeout)
            .then(|| ready.max(last_sent).max(last_output) + Duration::from_millis(self.idle_ms))
    }
}

pub(super) fn websocket_action_due(
    action: &InputAction,
    completed: &BTreeMap<u64, Instant>,
    last_offset: u64,
    last_sent: Instant,
    input_gap_ms: u64,
) -> Option<Instant> {
    let mut barrier = None;
    for sequence in &action.after {
        let at = *completed.get(sequence)?;
        barrier = Some(barrier.map_or(at, |previous: Instant| previous.max(at)));
    }
    let closes = matches!(
        action.action,
        InputActionKind::Close { .. } | InputActionKind::TransportEnd { .. }
    );
    if closes && let Some(gap_start) = action.gap_start_ms {
        let delay = action.offset_ms.checked_sub(gap_start)?;
        // Keep the actual completion barrier even when client idle time is compressed.
        return barrier?.checked_add(Duration::from_millis(delay));
    }
    if action.compressible_gap {
        let gap_start = action.gap_start_ms?;
        let delay = action.offset_ms.saturating_sub(gap_start).min(input_gap_ms);
        Some(barrier? + Duration::from_millis(delay))
    } else {
        let due = last_sent + Duration::from_millis(action.offset_ms.saturating_sub(last_offset));
        Some(barrier.map_or(due, |barrier| due.max(barrier)))
    }
}

/// Business inputs retain the Source dependency-delivery prefix even when no
/// business-completion profile makes their preceding gap compressible. Native
/// ACKs, heartbeat controls and cancellation must remain independently runnable.
pub(crate) fn delivery_prefix(action: &InputAction) -> bool {
    matches!(&action.action, InputActionKind::Message { message }
    if message.kind == MessageKind::Text
        && matches!(decode_engine_io_text(&message.data, usize::MAX),
            Ok(EngineIoPacket::Message(crate::interaction::socketio::SocketIoPacket {
                kind: SocketIoKind::Event | SocketIoKind::BinaryEvent, ..
            }))))
}

pub(crate) fn ordered_input(action: &InputAction) -> bool {
    action.ack_ref.is_some() || delivery_prefix(action)
}

pub(crate) fn namespace_disconnect(action: &InputAction, limit: usize) -> bool {
    matches!(&action.action, InputActionKind::Message { message }
        if message.kind == MessageKind::Text
        && matches!(decode_engine_io_text(&message.data, limit),
            Ok(EngineIoPacket::Message(packet)) if packet.kind == SocketIoKind::Disconnect))
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct Advance {
    pub removed_ms: u64,
}

/// A monotonic, piecewise mapping from Source offsets to replay offsets. A cut
/// flattens only an admitted idle suffix; later events inherit the same shift.
#[derive(Debug, Default)]
pub(crate) struct Clock {
    cuts: Vec<(u64, u64)>,
}

impl Clock {
    pub(crate) fn effective_ms(&self, source_ms: u64) -> u64 {
        source_ms
            - self
                .cuts
                .iter()
                .map(|&(from, to)| source_ms.min(to).saturating_sub(from))
                .sum::<u64>()
    }

    pub(crate) fn removed_ms(&self) -> u64 {
        self.cuts.iter().map(|(from, to)| to - from).sum()
    }

    pub(crate) fn compress(&mut self, from: u64, to: u64, elapsed_ms: u64, idle_ms: u64) {
        let from = from.max(self.cuts.last().map_or(0, |cut| cut.1));
        let removable = to.saturating_sub(from).saturating_sub(idle_ms);
        let remaining = self
            .effective_ms(to)
            .saturating_sub(elapsed_ms.saturating_add(idle_ms));
        let removed = removable.min(remaining);
        if removed > 0 {
            self.cuts.push((to - removed, to));
        }
    }
}

pub(crate) fn cancellation(action: &InputAction) -> bool {
    match &action.action {
        InputActionKind::Close { .. } | InputActionKind::TransportEnd { .. } => true,
        InputActionKind::Message { message } if message.kind == MessageKind::Text => {
            matches!(
                decode_engine_io_text(&message.data, usize::MAX),
                Ok(EngineIoPacket::Close)
                    | Ok(EngineIoPacket::Message(
                        crate::interaction::socketio::SocketIoPacket {
                            kind: SocketIoKind::Disconnect,
                            ..
                        }
                    ))
            )
        }
        _ => false,
    }
}

pub(crate) fn transport_cancellation(action: &InputAction) -> bool {
    action.after.is_empty()
        && (matches!(
            action.action,
            InputActionKind::Close { .. } | InputActionKind::TransportEnd { .. }
        ) || matches!(&action.action, InputActionKind::Message { message }
            if message.kind == MessageKind::Text && message.data == "1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_compresses_only_idle_and_moves_every_later_event() {
        let mut clock = Clock::default();
        clock.compress(2_000, 30_000, 3_000, 100);
        assert_eq!(clock.effective_ms(30_000), 3_100);
        assert_eq!(clock.effective_ms(40_000), 13_100);
        assert_eq!(clock.effective_ms(2_000), 2_000);
        assert!((0..50_000).all(|i| clock.effective_ms(i) <= clock.effective_ms(i + 1)));
        clock.compress(32_000, 40_000, 5_100, 100);
        assert_eq!(clock.effective_ms(40_000), 5_200);
        assert_eq!(clock.effective_ms(42_000), 7_200);
        let removed = clock.removed_ms();
        clock.compress(32_000, 40_000, 5_200, 100);
        assert_eq!(clock.removed_ms(), removed, "retries cannot compress twice");
    }
}
