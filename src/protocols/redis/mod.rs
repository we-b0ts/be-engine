//! Compose Redis recording with shared ownership, persistence and connection lifetime.
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use traffic_protocol::transport::ConnectionTermination;
use traffic_protocol_redis::capture::connection::{self, ConnectionOptions};
use uuid::Uuid;

use crate::AppState;
pub(crate) use connection::ConnectionContext;
mod host;
mod pubsub;
mod rpc;
#[cfg(test)]
mod tests;

pub(super) fn record_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    info: traffic_protocol::connection::ConnectionInfo,
) -> traffic_protocol::connection::NativeFuture<'static, ()> {
    Box::pin(async move {
        let upstream_addr = match info.upstream_addr {
            Some(address) => address,
            None => upstream.peer_addr()?.to_string(),
        };
        let context = ConnectionContext {
            client_addr: info.client_addr,
            target_addr: format!("{}:{}", info.endpoint.host, info.endpoint.port),
            target_host: info.endpoint.host,
            target_port: info.endpoint.port,
            upstream_addr,
        };
        handle_connected(client, upstream, state, context).await
    })
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let termination = ConnectionTermination::default();
    let _connection = state.dependency_connections().register_observed(
        "redis",
        &[&client, &upstream],
        &termination,
    )?;
    let options = ConnectionOptions {
        context: context.clone(),
        connection_id,
        max_frame_bytes: state.config().recording.max_body_bytes,
        client_decoder: crate::protocols::redis_session(state.dependency_providers())
            .context("failed to create Redis recording request decoder")?,
        server_decoder: crate::protocols::redis_session(state.dependency_providers())
            .context("failed to create Redis recording response decoder")?,
        termination,
    };
    connection::run(
        client,
        upstream,
        options,
        Arc::new(host::Host::new(state, context, connection_id)),
    )
    .await
}
