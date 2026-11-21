//! Payload-free acknowledgement correlation failures for recorder diagnostics.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckFailureKind {
    ClientIdentityInFlight,
    ClientAckUnobserved,
    ClientAckNotPending,
    ServerAckNotPending,
    ServerIdentityInFlight,
}

/// Only protocol identity is retained; namespaces and payloads stay private.
#[derive(Debug)]
pub struct AckObservationError {
    pub kind: AckFailureKind,
    pub ack_id: u64,
}

impl AckObservationError {
    pub fn new(kind: AckFailureKind, ack_id: u64) -> Self {
        Self { kind, ack_id }
    }

    pub fn diagnostic_code(&self) -> &'static str {
        match self.kind {
            AckFailureKind::ClientIdentityInFlight => "socketio_client_ack_overlap",
            AckFailureKind::ClientAckUnobserved => "socketio_client_ack_unobserved",
            AckFailureKind::ClientAckNotPending => "socketio_client_ack_not_pending",
            AckFailureKind::ServerAckNotPending => "socketio_server_ack_not_pending",
            AckFailureKind::ServerIdentityInFlight => "socketio_server_ack_overlap",
        }
    }
}

impl fmt::Display for AckObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            AckFailureKind::ClientIdentityInFlight => "overlapping Socket.IO ACK identities",
            AckFailureKind::ClientAckUnobserved => {
                "client ACK has no observed server-event binding"
            }
            AckFailureKind::ClientAckNotPending => {
                "client ACK does not match a pending server event"
            }
            AckFailureKind::ServerAckNotPending => {
                "server ACK does not match a pending client event"
            }
            AckFailureKind::ServerIdentityInFlight => "duplicate pending server ACK identity",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AckObservationError {}
