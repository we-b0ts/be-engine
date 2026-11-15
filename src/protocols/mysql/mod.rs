//! MySQL recording composition and application-owned policy/lifecycle ports.
use anyhow::{Context, Result};
use chrono::Utc;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use crate::dependency::termination::ConnectionTermination;
use crate::protocols::recording::events::{ProxyErrorEvent, RecorderEvent};
use crate::recording_control::RecordingListener;
use crate::{AppState, MysqlRouteConfig};
pub(crate) use traffic_protocol_mysql::capture::connection::CaptureConnectionContext as MysqlConnectionContext;
use traffic_protocol_mysql::capture::connection::{self, ConnectionOptions};

mod host;
mod ownership;
use ownership::record_event;
#[cfg(test)]
mod fifo_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::mysql::wire::{MysqlPacket, parse_handshake_response, read_packet};
#[cfg(test)]
use connection::write_packet;
#[cfg(test)]
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub async fn run(state: AppState) -> Result<()> {
    let routes = state.config().mysql.effective_routes();
    let mut bound_routes = Vec::with_capacity(routes.len());
    for route in routes {
        let listener = TcpListener::bind(route.listen)
            .await
            .with_context(|| format!("failed to bind MySQL proxy {}", route.listen))?;
        info!(
            route = route.name.as_deref().unwrap_or("unnamed"),
            listen = %route.listen,
            upstream = %route.upstream,
            "MySQL proxy listening"
        );
        bound_routes.push((route, listener));
    }
    state.mark_recording_listener_ready(RecordingListener::Mysql);
    let mut tasks = JoinSet::new();

    for (route, listener) in bound_routes {
        let state = state.clone();
        tasks.spawn(async move { run_route(state, route, listener).await });
    }

    match tasks.join_next().await {
        Some(result) => result.context("MySQL route task panicked")?,
        None => Ok(()),
    }
}

async fn run_route(state: AppState, route: MysqlRouteConfig, listener: TcpListener) -> Result<()> {
    loop {
        let (client, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept MySQL client")?;
        let state = state.clone();
        let route = route.clone();
        tokio::spawn(async move {
            let (target_host, target_port, target_addr) = mysql_target_from_addr(&route.upstream);
            let context = MysqlConnectionContext {
                route_name: route.name.clone(),
                listen_addr: route.listen.to_string(),
                client_addr: Some(peer_addr.to_string()),
                target_host,
                target_port,
                target_addr,
                upstream_addr: route.upstream.clone(),
            };
            if let Err(err) = handle_mysql_connection(client, state, context).await {
                warn!(error = %err, "MySQL proxy connection failed");
            }
        });
    }
}

async fn handle_mysql_connection(
    client: TcpStream,
    state: AppState,
    context: MysqlConnectionContext,
) -> Result<()> {
    let upstream_addr = context.upstream_addr.clone();
    let upstream =
        if let Some((host, port)) = context.target_host.as_deref().zip(context.target_port) {
            match crate::recorder::connect_failure::connect_upstream(
                &state,
                &client,
                "mysql",
                (host, port),
                &upstream_addr,
            )
            .await
            .context("failed to connect MySQL upstream")?
            {
                Some(stream) => stream,
                None => return Ok(()),
            }
        } else {
            match TcpStream::connect(&upstream_addr).await {
                Ok(stream) => stream,
                Err(error) => {
                    record_event_and_case_dependency(
                        &state,
                        RecorderEvent::ProxyError(ProxyErrorEvent {
                            id: Uuid::new_v4(),
                            connection_id: None,
                            timestamp: Utc::now(),
                            protocol: "mysql".into(),
                            client_addr: context.client_addr.clone(),
                            target: Some(upstream_addr),
                            error: error.to_string(),
                        }),
                    )
                    .await?;
                    return Err(error).context("failed to connect MySQL upstream");
                }
            }
        };

    handle_connected_mysql(client, upstream, state, context).await
}

pub(super) fn record_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    info: traffic_protocol::connection::ConnectionInfo,
) -> traffic_protocol::connection::NativeFuture<'static, ()> {
    Box::pin(async move {
        let endpoint = info.endpoint;
        let upstream_addr = match info.upstream_addr {
            Some(address) => address,
            None => upstream
                .peer_addr()
                .context("failed to read MySQL recording upstream address")?
                .to_string(),
        };
        let target_addr = if endpoint.port == 3306 {
            endpoint.host.clone()
        } else {
            format!("{}:{}", endpoint.host, endpoint.port)
        };
        let context = MysqlConnectionContext {
            route_name: Some(format!("fake-ip:{}", endpoint.host)),
            listen_addr: state.config().tcp_gateway.listen.to_string(),
            client_addr: info.client_addr,
            target_host: Some(endpoint.host),
            target_port: Some(endpoint.port),
            target_addr: Some(target_addr),
            upstream_addr,
        };
        handle_connected_mysql(client, upstream, state, context).await
    })
}

pub(crate) async fn handle_connected_mysql(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: MysqlConnectionContext,
) -> Result<()> {
    client
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for MySQL recording client")?;
    upstream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for MySQL recording upstream")?;
    let termination = ConnectionTermination::default();
    let _connection = state.dependency_connections().register_observed(
        "mysql",
        &[&client, &upstream],
        &termination,
    )?;
    let options = ConnectionOptions {
        context: context.clone(),
        max_body_bytes: state.config().recording.max_body_bytes,
        record_raw_packets: state.config().mysql.record_raw_packets,
        client_decoder: crate::protocols::mysql_session(state.dependency_providers())?,
        server_decoder: crate::protocols::mysql_session(state.dependency_providers())?,
        termination,
    };
    connection::run(
        client,
        upstream,
        options,
        Arc::new(host::Host::new(state, context)),
    )
    .await
}

fn mysql_target_from_addr(addr: &str) -> (Option<String>, Option<u16>, Option<String>) {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return (None, None, None);
    }
    if let Ok(socket_addr) = trimmed.parse::<std::net::SocketAddr>() {
        return (
            Some(socket_addr.ip().to_string()),
            Some(socket_addr.port()),
            Some(socket_addr.to_string()),
        );
    }
    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return (Some(trimmed.to_string()), None, Some(trimmed.to_string()));
    };
    let port = port.parse::<u16>().ok();
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let target_addr = port.map(|port| format!("{host}:{port}"));
    (
        Some(host),
        port,
        target_addr.or_else(|| Some(trimmed.to_string())),
    )
}

async fn record_event_and_case_dependency(state: &AppState, event: RecorderEvent) -> Result<()> {
    let targets = state.capture_dependency_targets();
    record_event(state, event, Some(targets)).await
}
