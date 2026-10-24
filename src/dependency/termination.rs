//! Peer observations, separate from recorder-owned shutdown and parsing.
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::{
    DependencyExchangeOutcome, DependencyTermination, TerminationKind, TerminationScope,
    TerminationSide,
};

mod control;
mod forwarding;
mod observation;
pub(crate) use control::ConnectionControl;
pub(crate) use forwarding::forward_captured;
pub(crate) use observation::ObservedIo;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObservedTermination {
    pub(crate) termination: DependencyTermination,
    pub(crate) at: Instant,
}

/// Project an independently observed monotonic end into the event wall clock.
/// A delayed recorder finalizer must not move an earlier peer end past Source stop.
pub(crate) fn observed_wall_time(at: Instant) -> chrono::DateTime<chrono::Utc> {
    let wall = chrono::Utc::now();
    chrono::TimeDelta::from_std(Instant::now().saturating_duration_since(at))
        .ok()
        .and_then(|lag| wall.checked_sub_signed(lag))
        .unwrap_or(wall)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ConnectionTermination {
    state: Arc<Mutex<TerminationState>>,
}

#[derive(Debug, Default)]
struct TerminationState {
    first: Option<ObservedTermination>,
    client: PeerTermination,
    server: PeerTermination,
    engine_stopped: bool,
}

#[derive(Debug, Default)]
struct PeerTermination {
    first: Option<ObservedTermination>,
    connection_end: Option<ObservedTermination>,
}

impl ConnectionTermination {
    pub(crate) fn observe_client_eof(&self) {
        self.observe_eof(TerminationSide::Client);
    }
    pub(crate) fn observe_server_eof(&self) {
        self.observe_eof(TerminationSide::Server);
    }

    pub(crate) fn observe_eof(&self, side: TerminationSide) {
        self.observe(DependencyTermination {
            side,
            kind: TerminationKind::Eof,
            scope: TerminationScope::WriteHalf,
        });
    }

    pub(crate) fn observe_engine_stop(&self) {
        let mut state = self.state.lock().expect("connection termination poisoned");
        state.engine_stopped = true;
        state.first.get_or_insert_with(|| ObservedTermination {
            termination: DependencyTermination {
                side: TerminationSide::Engine,
                kind: TerminationKind::Cancelled,
                scope: TerminationScope::Connection,
            },
            at: Instant::now(),
        });
    }

    pub(crate) fn observe_client_error(&self, error: &anyhow::Error) -> bool {
        self.observe_error(TerminationSide::Client, error)
    }
    pub(crate) fn observe_server_error(&self, error: &anyhow::Error) -> bool {
        self.observe_error(TerminationSide::Server, error)
    }

    fn observe_error(&self, side: TerminationSide, error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| self.observe_io_error(side, error))
        })
    }

    pub(crate) fn observe_client_io_error(&self, error: &std::io::Error) -> bool {
        self.observe_io_error(TerminationSide::Client, error)
    }

    pub(crate) fn observe_io_error(&self, side: TerminationSide, error: &std::io::Error) -> bool {
        if is_connection_termination(error.kind()) {
            // A failed write alone does not establish which peer action ended
            // the transport. Keep it recognizable, but require an independent
            // EOF/reset observation before certifying replayable evidence.
            if matches!(
                error.kind(),
                ErrorKind::BrokenPipe | ErrorKind::NotConnected
            ) {
                return true;
            }
            self.observe(DependencyTermination {
                side,
                kind: if error.kind() == ErrorKind::UnexpectedEof {
                    TerminationKind::Eof
                } else {
                    TerminationKind::Reset
                },
                scope: if error.kind() == ErrorKind::UnexpectedEof {
                    TerminationScope::WriteHalf
                } else {
                    TerminationScope::Connection
                },
            });
            true
        } else {
            false
        }
    }

    pub(crate) fn snapshot(&self) -> Option<ObservedTermination> {
        self.state
            .lock()
            .expect("connection termination poisoned")
            .first
    }

    pub(crate) fn peer_snapshot(&self) -> Option<ObservedTermination> {
        let state = self.state.lock().expect("connection termination poisoned");
        if state.engine_stopped {
            None
        } else {
            state
                .first
                .filter(|end| end.termination.side != TerminationSide::Engine)
        }
    }

    /// Keep each direction's fact for transparent forwarding after a half-close.
    /// Exchange ownership still uses the first overall observation. Cleanup is
    /// excluded here just as it is from replayable exchange evidence.
    pub(crate) fn observed(&self, side: TerminationSide) -> Option<ObservedTermination> {
        let state = self.state.lock().expect("connection termination poisoned");
        if state.engine_stopped {
            return None;
        }
        match side {
            TerminationSide::Client => state.client.first,
            TerminationSide::Server => state.server.first,
            TerminationSide::Engine => None,
        }
    }

    /// EOF ends only one write direction. A later reset is independent evidence
    /// that the connection ended, without rewriting the earlier half-close.
    pub(crate) fn connection_end(&self, side: TerminationSide) -> Option<ObservedTermination> {
        let state = self.state.lock().expect("connection termination poisoned");
        if state.engine_stopped {
            return None;
        }
        match side {
            TerminationSide::Client => state.client.connection_end,
            TerminationSide::Server => state.server.connection_end,
            TerminationSide::Engine => None,
        }
    }

    pub(crate) fn engine_stopped(&self) -> bool {
        self.state
            .lock()
            .expect("connection termination poisoned")
            .engine_stopped
    }

    /// Engine-owned cleanup cannot certify a peer's replayable termination.
    pub(crate) fn outcome_since(
        &self,
        started: Instant,
    ) -> Option<(DependencyExchangeOutcome, u128)> {
        let end = self.peer_snapshot()?;
        let duration = end.at.checked_duration_since(started)?;
        Some((
            DependencyExchangeOutcome::Terminated(end.termination),
            duration.as_millis(),
        ))
    }

    fn observe(&self, termination: DependencyTermination) {
        let mut state = self.state.lock().expect("connection termination poisoned");
        let observed = ObservedTermination {
            termination,
            at: Instant::now(),
        };
        state.first.get_or_insert(observed);
        let peer = match termination.side {
            TerminationSide::Client => &mut state.client,
            TerminationSide::Server => &mut state.server,
            TerminationSide::Engine => return,
        };
        peer.first.get_or_insert(observed);
        if termination.scope == TerminationScope::Connection {
            peer.connection_end.get_or_insert(observed);
        }
    }
}

pub(crate) fn is_connection_termination(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_first_observation_and_its_clock() {
        let termination = ConnectionTermination::default();
        let started = Instant::now();
        termination.observe_client_eof();
        let observed = termination.snapshot().unwrap();
        termination.observe_server_eof();
        assert_eq!(termination.snapshot().unwrap().at, observed.at);
        assert_eq!(
            termination.observed(TerminationSide::Client).unwrap().at,
            observed.at
        );
        assert_eq!(
            termination
                .observed(TerminationSide::Server)
                .unwrap()
                .termination
                .side,
            TerminationSide::Server
        );
        assert_eq!(
            termination.snapshot().unwrap().termination.side,
            TerminationSide::Client
        );
        assert!(
            termination
                .outcome_since(started)
                .unwrap()
                .0
                .is_client_terminated()
        );
    }

    #[test]
    fn engine_cleanup_is_not_peer_evidence() {
        let termination = ConnectionTermination::default();
        termination.observe_engine_stop();
        termination.observe_client_eof();
        assert!(termination.outcome_since(Instant::now()).is_none());
        assert_eq!(
            termination.snapshot().unwrap().termination.side,
            TerminationSide::Engine
        );
        let termination = ConnectionTermination::default();
        termination.observe_client_eof();
        termination.observe_engine_stop();
        assert!(termination.outcome_since(Instant::now()).is_none());
        assert!(termination.observed(TerminationSide::Client).is_none());
    }

    #[test]
    fn broken_pipe_does_not_invent_a_peer_reset() {
        let termination = ConnectionTermination::default();
        assert!(termination.observe_client_io_error(&std::io::Error::from(ErrorKind::BrokenPipe)));
        assert!(termination.snapshot().is_none());
        termination.observe_client_eof();
        assert_eq!(
            termination.snapshot().unwrap().termination.kind,
            TerminationKind::Eof
        );
    }

    #[test]
    fn a_later_reset_does_not_rewrite_the_first_half_close() {
        let termination = ConnectionTermination::default();
        termination.observe_client_eof();
        let half_close = termination.observed(TerminationSide::Client).unwrap();
        assert!(
            termination
                .connection_end(TerminationSide::Client)
                .is_none()
        );
        termination.observe_client_io_error(&std::io::ErrorKind::ConnectionReset.into());
        assert_eq!(termination.snapshot().unwrap().at, half_close.at);
        assert_eq!(
            termination
                .observed(TerminationSide::Client)
                .unwrap()
                .termination
                .kind,
            TerminationKind::Eof
        );
        assert_eq!(
            termination
                .connection_end(TerminationSide::Client)
                .unwrap()
                .termination
                .kind,
            TerminationKind::Reset
        );
        termination.observe_engine_stop();
        assert!(
            termination
                .connection_end(TerminationSide::Client)
                .is_none()
        );
    }

    #[test]
    fn an_earlier_connection_event_does_not_end_a_later_request() {
        let termination = ConnectionTermination::default();
        termination.observe_server_eof();
        let after = termination.snapshot().unwrap().at + std::time::Duration::from_millis(1);
        assert!(termination.outcome_since(after).is_none());
    }
}
