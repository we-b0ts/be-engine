//! Bounded diagnostics and the narrow set of observed client transport losses.
use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};

pub(super) fn client_lost(error: &Error) -> bool {
    matches!(
        error,
        Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)
    ) || matches!(error, Error::Io(error) if matches!(error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof))
}

/// Never format errors that may contain frames, URLs, headers or peer text.
pub(super) fn kind(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<Error>() {
        Some(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => "eof_without_close",
        Some(Error::Io(error)) => match error.kind() {
            std::io::ErrorKind::ConnectionReset => "connection_reset",
            std::io::ErrorKind::ConnectionAborted => "connection_aborted",
            std::io::ErrorKind::BrokenPipe => "broken_pipe",
            std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
            std::io::ErrorKind::TimedOut => "io_timeout",
            _ => "io_error",
        },
        Some(Error::Protocol(_)) => "websocket_protocol_error",
        Some(Error::Capacity(_)) => "websocket_capacity_exceeded",
        Some(Error::Utf8(_)) => "websocket_invalid_utf8",
        Some(Error::ConnectionClosed) => "websocket_closed",
        Some(Error::AlreadyClosed) => "websocket_already_closed",
        Some(_) => "websocket_error",
        None if error.is::<super::closing::ConfirmationFailure>() => {
            "application_close_confirmation"
        }
        None => "observation_or_upgrade_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_observed_disconnects_qualify_and_diagnostics_exclude_private_text() {
        for io in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = Error::Io(std::io::Error::new(io, "private peer text"));
            assert!(client_lost(&error));
            assert!(!kind(&error.into()).contains("private"));
        }
        for error in [
            Error::Utf8("private frame".into()),
            Error::Protocol(ProtocolError::UnmaskedFrameFromClient),
            Error::AlreadyClosed,
            Error::Io(std::io::Error::other("private io context")),
        ] {
            assert!(!client_lost(&error));
            assert!(!kind(&error.into()).contains("private"));
        }
    }
}
