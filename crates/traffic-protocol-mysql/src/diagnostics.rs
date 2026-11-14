//! Opt-in protocol envelopes, without SQL, parameters, column names or row values.
use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;

use crate::MysqlPacket;

const TARGET: &str = "traffic_e2e::replay::mysql::wire_diagnostics";

struct Connection {
    id: uuid::Uuid,
    peer: SocketAddr,
    request: u64,
    response_kind: &'static str,
    status_flags: Option<u16>,
}

tokio::task_local! {
    static CONNECTION: RefCell<Connection>;
}

pub async fn connection<T>(peer: SocketAddr, operation: impl Future<Output = T>) -> T {
    if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
        return operation.await;
    }
    CONNECTION
        .scope(
            RefCell::new(Connection {
                id: uuid::Uuid::new_v4(),
                peer,
                request: 0,
                response_kind: "handshake",
                status_flags: None,
            }),
            operation,
        )
        .await
}

pub fn request(packet: &MysqlPacket, command: &str) {
    let _ = CONNECTION.try_with(|connection| {
        let mut connection = connection.borrow_mut();
        connection.request = connection.request.saturating_add(1);
        connection.response_kind = "unclassified";
        connection.status_flags = None;
        tracing::debug!(target: TARGET, connection_id=%connection.id, peer=%connection.peer,
            request=connection.request, packet_sequence=packet.sequence_id,
            payload_bytes=packet.payload.len(), command, "MySQL received command");
    });
}

pub fn response_kind(kind: &'static str, status_flags: Option<u16>) {
    let _ = CONNECTION.try_with(|connection| {
        let mut connection = connection.borrow_mut();
        connection.response_kind = kind;
        connection.status_flags = status_flags;
    });
}

pub fn active() -> bool {
    CONNECTION.try_with(|_| ()).is_ok()
}

pub fn response(packet: &MysqlPacket, next_sequence: Option<u8>) {
    response_envelope(
        packet.sequence_id,
        packet.payload.len(),
        packet.payload.first().copied(),
        next_sequence,
    );
}

pub fn response_envelope(
    sequence: u8,
    payload_bytes: usize,
    leading_byte: Option<u8>,
    next_sequence: Option<u8>,
) {
    let _ = CONNECTION.try_with(|connection| {
        let connection = connection.borrow();
        tracing::debug!(target: TARGET, connection_id=%connection.id, peer=%connection.peer,
            request=connection.request, packet_sequence=sequence,
            next_packet_sequence=?next_sequence, payload_bytes,
            response_kind=connection.response_kind, status_flags=?connection.status_flags,
            leading_byte=?leading_byte, buffered=next_sequence.is_some(),
            "MySQL response message write completed; transport flush is separate");
    });
}

pub fn flushed(success: bool) {
    event("transport_flush", Some(success));
}

pub fn client_eof() {
    event("client_eof", None);
}

fn event(kind: &str, success: Option<bool>) {
    let _ = CONNECTION.try_with(|connection| {
        let connection = connection.borrow();
        tracing::debug!(target: TARGET, connection_id=%connection.id, peer=%connection.peer,
            request=connection.request, kind, success=?success, "MySQL connection observation");
    });
}

#[cfg(any(test, feature = "test-support"))]
pub fn request_number() -> Option<u64> {
    CONNECTION
        .try_with(|connection| connection.borrow().request)
        .ok()
}
