//! Explicit client endings retain pending work without inventing completions.
use super::{InputTime, Observation};
use crate::interaction::model::{
    ClientTransportEnd, CloseObservation, InputAction, InputActionKind, Protocol,
};
use anyhow::{Result, ensure};

impl Observation {
    pub fn client_close(
        &mut self,
        code: Option<u16>,
        reason: String,
        now: impl Into<InputTime>,
    ) -> Result<InputAction> {
        let InputTime { ms: now_ms, us } = now.into();
        self.ensure_client_transport_open()?;
        let completed = self
            .close_barrier
            .as_ref()
            .filter(|_| self.lifecycle.pending().is_empty());
        self.close = Some(CloseObservation {
            code,
            reason: reason.clone(),
        });
        let action = InputAction {
            sequence: self.next_input,
            offset_ms: now_ms,
            offset_us: us,
            after: completed.map_or_else(Vec::new, |(ids, _)| ids.clone()),
            compressible_gap: false,
            gap_start_ms: completed.map(|(_, at)| *at),
            ack_ref: None,
            action: InputActionKind::Close { code, reason },
        };
        self.next_input += 1;
        self.input.actions.push(action.clone());
        Ok(action)
    }

    pub fn server_close(&mut self, code: Option<u16>, reason: String) {
        self.server_end_observed = true;
        self.close = Some(CloseObservation { code, reason });
    }

    pub(super) fn ensure_client_transport_open(&self) -> Result<()> {
        ensure!(
            !self.input.actions.last().is_some_and(|action| matches!(
                action.action,
                InputActionKind::TransportEnd { .. }
            )),
            "client input follows recorded transport termination"
        );
        Ok(())
    }

    /// Record only an actually observed end at complete logical-message boundaries.
    /// The transport owner separately proves raw framing and Source cleanup.
    pub fn client_transport_end(
        &mut self,
        end: ClientTransportEnd,
        now: impl Into<InputTime>,
    ) -> Result<InputAction> {
        let InputTime { ms: now_ms, us } = now.into();
        self.ensure_client_transport_open()?;
        ensure!(
            matches!(self.protocol, Protocol::SocketIo | Protocol::WebSocket),
            "client transport termination requires a WebSocket interaction"
        );
        self.client_decoder.finish()?;
        self.server_decoder.finish()?;
        ensure!(
            self.input
                .actions
                .last()
                .is_none_or(|action| now_ms >= action.offset_ms),
            "client transport termination predates an observed input"
        );
        let action = InputAction {
            sequence: self.next_input,
            offset_ms: now_ms,
            offset_us: us,
            after: vec![],
            compressible_gap: false,
            gap_start_ms: None,
            ack_ref: None,
            action: InputActionKind::TransportEnd { end },
        };
        self.input.actions.push(action.clone());
        self.next_input += 1;
        self.safe_barrier = None;
        if self.protocol == Protocol::SocketIo {
            self.input.socket_io_heartbeat = Some(self.heartbeats.program());
        }
        Ok(action)
    }
}

#[cfg(test)]
mod tests;
