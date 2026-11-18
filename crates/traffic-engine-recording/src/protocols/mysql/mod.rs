//! Test fixtures for the registered MySQL recording entrypoint.
use crate::AppState;
use crate::mysql::wire::{MysqlPacket, parse_handshake_response, read_packet};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
pub use traffic_protocol_mysql::capture::connection::CaptureConnectionContext as MysqlConnectionContext;
use traffic_protocol_mysql::write_packet;
mod fifo_tests;
mod tests;

pub async fn handle_connected_mysql(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: MysqlConnectionContext,
) -> Result<()> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    let endpoint = context
        .target_host
        .zip(context.target_port)
        .map(|(host, port)| traffic_protocol::connection::Endpoint { host, port })
        .or_else(|| traffic_protocol::connection::endpoint_from_addr(&context.upstream_addr))
        .context("MySQL recording endpoint is unavailable")?;
    let info = traffic_protocol::connection::ConnectionInfo {
        endpoint,
        client_addr: context.client_addr,
        upstream_addr: Some(context.upstream_addr),
        max_frame_bytes: state.config().recording.max_body_bytes,
    };
    crate::recorder::native::handle_connected(
        crate::protocols::DependencyProtocol::Mysql,
        client,
        upstream,
        state,
        info,
    )
    .await
}
