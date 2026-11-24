//! Integrity checks for the independently progressing primary exchanges.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, ensure};
use traffic_model::session::SessionEvent;
use uuid::Uuid;

#[derive(Default, PartialEq, Eq)]
enum Phase {
    #[default]
    AwaitingSource,
    Starting,
    Ready,
    Stopping,
    Exited,
}

#[derive(Default)]
pub(super) struct SessionCapture {
    phase: Phase,
    ready: bool,
    known: HashSet<Uuid>,
    pending: HashMap<Uuid, Exchange>,
}

#[derive(Default)]
struct Exchange {
    next_part: Option<u64>,
    trailers: bool,
}

impl SessionCapture {
    pub(super) fn observe(&mut self, event: &SessionEvent) -> Result<()> {
        use SessionEvent::*;
        match event {
            SourceStart => self.transition(Phase::AwaitingSource, Phase::Starting)?,
            Ready => {
                self.transition(Phase::Starting, Phase::Ready)?;
                self.ready = true;
            }
            Stop => {
                ensure!(
                    matches!(self.phase, Phase::Starting | Phase::Ready),
                    "out-of-order Source session lifecycle"
                );
                self.phase = Phase::Stopping;
            }
            SourceExit { .. } => self.transition(Phase::Stopping, Phase::Exited)?,
            PrimaryRequest { exchange, .. } => {
                ensure!(
                    matches!(self.phase, Phase::Starting | Phase::Ready),
                    "primary request is outside Source admission"
                );
                ensure!(self.known.insert(*exchange), "duplicate primary request");
                self.pending.insert(*exchange, Exchange::default());
            }
            PrimaryResponseHeaders { exchange, .. } => {
                let parts = &mut self.exchange(exchange)?.next_part;
                ensure!(parts.is_none(), "duplicate primary response headers");
                *parts = Some(1);
            }
            PrimaryResponsePart { exchange, part, .. } => {
                let exchange = self.exchange(exchange)?;
                ensure!(!exchange.trailers, "response part followed its trailers");
                let next = exchange
                    .next_part
                    .as_mut()
                    .context("response part preceded its headers")?;
                ensure!(*part == *next, "unordered primary response part");
                *next = next
                    .checked_add(1)
                    .context("too many primary response parts")?;
            }
            PrimaryResponseTrailers { exchange, .. } => {
                let state = self.exchange(exchange)?;
                ensure!(
                    state.next_part.is_some() && !state.trailers,
                    "out-of-order primary response trailers"
                );
                state.trailers = true;
            }
            PrimaryResponseEnd { exchange } => {
                ensure!(
                    self.exchange(exchange)?.next_part.is_some(),
                    "response end preceded its headers"
                );
                self.pending.remove(exchange);
            }
            PrimaryCancel { exchange, .. } => {
                self.exchange(exchange)?;
                self.pending.remove(exchange);
            }
        }
        Ok(())
    }

    fn exchange(&mut self, id: &Uuid) -> Result<&mut Exchange> {
        self.pending
            .get_mut(id)
            .context("primary event has no active request")
    }

    fn transition(&mut self, previous: Phase, next: Phase) -> Result<()> {
        ensure!(
            self.phase == previous,
            "out-of-order Source session lifecycle"
        );
        self.phase = next;
        Ok(())
    }

    pub(super) fn complete(&self) -> bool {
        self.ready && self.phase == Phase::Exited && self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_failure_keeps_its_exit_evidence_without_sealing_complete_capture() {
        let mut capture = SessionCapture::default();
        capture.observe(&SessionEvent::SourceStart).unwrap();
        capture.observe(&SessionEvent::Stop).unwrap();
        capture
            .observe(&SessionEvent::SourceExit { status: Some(1) })
            .unwrap();
        assert!(!capture.complete());
        assert!(capture.observe(&SessionEvent::Ready).is_err());
    }
}
