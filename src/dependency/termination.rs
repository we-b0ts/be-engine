use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

const NONE: u8 = 0;
const CLIENT_EOF: u8 = 1;
const CLIENT_RESET: u8 = 2;
const SERVER_EOF: u8 = 3;
const SERVER_RESET: u8 = 4;

#[derive(Debug, Clone, Default)]
pub(crate) struct ConnectionTermination {
    first: Arc<AtomicU8>,
}

impl ConnectionTermination {
    pub(crate) fn observe_client_eof(&self) {
        self.observe(CLIENT_EOF);
    }

    pub(crate) fn observe_server_eof(&self) {
        self.observe(SERVER_EOF);
    }

    pub(crate) fn observe_client_error(&self, error: &anyhow::Error) -> bool {
        if connection_error_kind(error).is_some_and(is_connection_termination) {
            self.observe(CLIENT_RESET);
            true
        } else {
            false
        }
    }

    pub(crate) fn observe_client_io_error(&self, error: &std::io::Error) -> bool {
        if is_connection_termination(error.kind()) {
            self.observe(CLIENT_RESET);
            true
        } else {
            false
        }
    }

    pub(crate) fn observe_server_error(&self, error: &anyhow::Error) -> bool {
        if connection_error_kind(error).is_some_and(is_connection_termination) {
            self.observe(SERVER_RESET);
            true
        } else {
            false
        }
    }

    pub(crate) fn client_ended_first(&self) -> bool {
        matches!(
            self.first.load(Ordering::Acquire),
            CLIENT_EOF | CLIENT_RESET
        )
    }

    fn observe(&self, termination: u8) {
        let _ = self
            .first
            .compare_exchange(NONE, termination, Ordering::AcqRel, Ordering::Acquire);
    }
}

fn connection_error_kind(error: &anyhow::Error) -> Option<ErrorKind> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
    })
}

fn is_connection_termination(kind: ErrorKind) -> bool {
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
    fn preserves_the_first_connection_side() {
        let termination = ConnectionTermination::default();
        termination.observe_client_eof();
        termination.observe_server_eof();
        assert!(termination.client_ended_first());

        let termination = ConnectionTermination::default();
        termination.observe_server_eof();
        termination.observe_client_eof();
        assert!(!termination.client_ended_first());
    }
}
