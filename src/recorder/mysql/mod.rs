use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::MysqlRouteConfig;
use crate::access_policy::{AccessDecision, MysqlAccessContext, evaluate_mysql_access};
use crate::dependency::termination::ConnectionTermination;
use crate::mysql::access::analyze_command;
use crate::mysql::wire::{
    MysqlPacket, ServerPacketInfo, clear_client_compression_capability,
    clear_server_compression_capability, parse_client_command, parse_handshake_response,
    parse_server_packet, read_packet, readonly_error_packet,
};
use crate::recorder::{
    MysqlConnectionEvent, MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket,
    ProxyErrorEvent, RecorderEvent, capture_body, capture_body_with_original_len,
};
use crate::recording_control::RecordingListener;

#[cfg(test)]
mod fifo_tests;
mod ownership;
mod response;
mod semantic;
#[cfg(test)]
mod tests;
mod tls;
mod tracker;

use ownership::{QueryDependencyOwnerships, record_event, record_query_completion};
#[cfg(test)]
use response::MysqlResponseTracker;
use semantic::MysqlExchangeContext;
use tracker::MysqlQueryTracker;

trait MysqlIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> MysqlIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type BoxedMysqlIo = Box<dyn MysqlIo>;

#[derive(Debug, Clone)]
pub(crate) struct MysqlConnectionContext {
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub upstream_addr: String,
}

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
    let upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            record_event_and_case_dependency(
                &state,
                RecorderEvent::ProxyError(ProxyErrorEvent {
                    id: Uuid::new_v4(),
                    connection_id: None,
                    timestamp: Utc::now(),
                    protocol: "mysql".to_string(),
                    client_addr: context.client_addr.clone(),
                    target: Some(upstream_addr),
                    error: err.to_string(),
                }),
            )
            .await?;
            return Err(err).context("failed to connect MySQL upstream");
        }
    };

    handle_connected_mysql(client, upstream, state, context).await
}

pub(crate) async fn handle_connected_mysql(
    mut client: TcpStream,
    mut upstream: TcpStream,
    state: AppState,
    context: MysqlConnectionContext,
) -> Result<()> {
    client
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for MySQL recording client")?;
    upstream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for MySQL recording upstream")?;
    let connection_id = Uuid::new_v4();
    let started = Instant::now();
    let route_name = context.route_name.clone();
    let listen_addr = context.listen_addr.clone();
    let client_addr = context.client_addr.clone();
    let target_host = context.target_host.clone();
    let target_port = context.target_port;
    let target_addr = context.target_addr.clone();
    let upstream_addr = context.upstream_addr.clone();

    let mut server_to_client_bytes = 0_u64;
    let mut client_to_server_bytes = 0_u64;

    let mut handshake = read_packet(&mut upstream)
        .await
        .context("failed to read MySQL upstream handshake")?
        .context("MySQL upstream closed before handshake")?;
    // Semantic capture parses ordinary MySQL packets. Negotiate compression
    // off before either peer can switch to the seven-byte compressed header.
    clear_server_compression_capability(&mut handshake);
    server_to_client_bytes += handshake.encoded_len() as u64;
    client
        .write_all(&handshake.to_wire_bytes())
        .await
        .context("failed to forward MySQL handshake")?;

    let mut login_packet = read_packet(&mut client)
        .await
        .context("failed to read MySQL login packet")?
        .context("MySQL client closed before login packet")?;
    clear_client_compression_capability(&mut login_packet);
    client_to_server_bytes += login_packet.encoded_len() as u64;
    let mut login = parse_handshake_response(&login_packet);

    let (client, upstream): (BoxedMysqlIo, BoxedMysqlIo) = if login.tls_requested {
        upstream
            .write_all(&login_packet.to_wire_bytes())
            .await
            .context("failed to forward MySQL SSL request")?;

        let tls_host = target_host
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let downstream_config = state.ca().mysql_server_config_for_host(&tls_host)?;
        let server_name = rustls::pki_types::ServerName::try_from(tls_host.clone())
            .with_context(|| format!("invalid MySQL TLS server name {tls_host}"))?;
        let accept_downstream = async {
            TlsAcceptor::from(downstream_config)
                .accept(client)
                .await
                .context("failed to accept MySQL client TLS")
        };
        let connect_upstream = async {
            TlsConnector::from(tls::upstream_client_config())
                .connect(server_name, upstream)
                .await
                .context("failed to establish MySQL upstream TLS")
        };
        let (mut client_tls, mut upstream_tls) =
            tokio::try_join!(accept_downstream, connect_upstream)?;

        let mut secure_login_packet = read_packet(&mut client_tls)
            .await
            .context("failed to read MySQL TLS login packet")?
            .context("MySQL TLS client closed before login packet")?;
        clear_client_compression_capability(&mut secure_login_packet);
        client_to_server_bytes += secure_login_packet.encoded_len() as u64;
        login = parse_handshake_response(&secure_login_packet);
        upstream_tls
            .write_all(&secure_login_packet.to_wire_bytes())
            .await
            .context("failed to forward MySQL TLS login packet")?;
        (Box::new(client_tls), Box::new(upstream_tls))
    } else {
        upstream
            .write_all(&login_packet.to_wire_bytes())
            .await
            .context("failed to forward MySQL login packet")?;
        (Box::new(client), Box::new(upstream))
    };

    let redacted_connection = MysqlConnectionEvent {
        id: connection_id,
        timestamp: Utc::now(),
        route_name: route_name.clone(),
        listen_addr: listen_addr.clone(),
        client_addr: client_addr.clone(),
        upstream_addr: upstream_addr.clone(),
        target_host: target_host.clone(),
        target_port,
        target_addr: target_addr.clone(),
        username: login.username.clone(),
        database: login.database.clone(),
        capability_flags: Some(login.capability_flags),
        duration_ms: None,
        client_to_server_bytes,
        server_to_client_bytes,
        error: None,
    };
    record_event_and_case_dependency(&state, RecorderEvent::MysqlConnection(redacted_connection))
        .await?;

    let authenticated = Arc::new(AtomicBool::new(false));
    let query_sequence = Arc::new(AtomicU64::new(0));
    let query_tracker = Arc::new(Mutex::new(MysqlQueryTracker::new(
        state.config().recording.max_body_bytes,
        state.config().mysql.record_raw_packets,
        MysqlExchangeContext {
            route_name: route_name.clone(),
            target_host: target_host.clone(),
            target_port,
            target_addr: target_addr.clone(),
            upstream_addr: Some(upstream_addr.clone()),
            username: login.username.clone(),
            database: login.database.clone(),
        },
    )));
    let dependency_ownerships = QueryDependencyOwnerships::default();
    let termination = ConnectionTermination::default();
    let (mut client_read, client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let client_write = Arc::new(Mutex::new(client_write));

    let c2s_state = state.clone();
    let c2s_client_addr = client_addr.clone();
    let c2s_authenticated = authenticated.clone();
    let c2s_query_sequence = query_sequence.clone();
    let c2s_connection_id = connection_id;
    let c2s_query_tracker = query_tracker.clone();
    let c2s_dependency_ownerships = dependency_ownerships.clone();
    let c2s_client_write = client_write.clone();
    let c2s_route_name = route_name.clone();
    let c2s_target_host = target_host.clone();
    let c2s_target_addr = target_addr.clone();
    let c2s_target = target_addr
        .clone()
        .or_else(|| target_host.clone())
        .or_else(|| Some(upstream_addr.clone()));
    let c2s_termination = termination.clone();
    let client_to_server = tokio::spawn(async move {
        let mut bytes = 0_u64;
        loop {
            let packet = match read_packet(&mut client_read).await {
                Ok(Some(packet)) => packet,
                Ok(None) => {
                    c2s_termination.observe_client_eof();
                    break;
                }
                Err(error) if c2s_termination.observe_client_io_error(&error) => break,
                Err(error) => return Err(error.into()),
            };
            bytes += packet.encoded_len() as u64;
            if c2s_authenticated.load(Ordering::SeqCst)
                && let Some(command) = parse_client_command(&packet)
            {
                let dependency_ownership = c2s_state.capture_dependency_targets();
                let (prepared_sql, current_database) = {
                    let tracker = c2s_query_tracker.lock().await;
                    let prepared_sql = if command.command_name == "COM_STMT_EXECUTE" {
                        tracker
                            .prepared_sql_for_packet(&packet)
                            .map(ToOwned::to_owned)
                    } else {
                        None
                    };
                    (prepared_sql, tracker.database().map(ToOwned::to_owned))
                };
                let analysis = analyze_command(&command, prepared_sql.as_deref());
                let access = evaluate_mysql_access(
                    c2s_state.config().recording.access_policy,
                    &c2s_state.config().recording.access_rules,
                    &analysis,
                    MysqlAccessContext {
                        route_name: c2s_route_name.as_deref(),
                        target_host: c2s_target_host.as_deref(),
                        target_addr: c2s_target_addr.as_deref(),
                        database: current_database.as_deref(),
                    },
                );
                if access.decision == AccessDecision::Reject {
                    c2s_state
                        .record_readonly_rejection(
                            "mysql",
                            analysis.class,
                            command.command_name,
                            c2s_client_addr.clone(),
                            c2s_target.clone(),
                            "MySQL command is classified as a write operation",
                        )
                        .await;
                    c2s_client_write
                        .lock()
                        .await
                        .write_all(
                            &readonly_error_packet(packet.sequence_id.wrapping_add(1))
                                .to_wire_bytes(),
                        )
                        .await?;
                    drop(dependency_ownership);
                    continue;
                }
                if let Some(rule) = access.matched_rule {
                    c2s_state
                        .record_access_policy_allow(
                            rule,
                            "mysql",
                            analysis.class,
                            analysis.operation_names(),
                            analysis.resource_names(current_database.as_deref()),
                            c2s_client_addr.clone(),
                            c2s_target.clone(),
                            "MySQL write matched a configured recording access rule",
                        )
                        .await;
                }
                let sequence = c2s_query_sequence.fetch_add(1, Ordering::SeqCst) + 1;
                c2s_dependency_ownerships.insert(sequence, dependency_ownership);
                let expects_server_response = command.expects_server_response();
                let closes_connection = command.command_name == "COM_QUIT";
                if closes_connection {
                    c2s_termination.observe_client_eof();
                }
                {
                    let mut tracker = c2s_query_tracker.lock().await;
                    if expects_server_response {
                        tracker.start_query(
                            c2s_connection_id,
                            sequence,
                            &command,
                            &packet,
                            c2s_client_addr.clone(),
                        )?;
                    } else {
                        tracker.observe_no_response_command(&command, &packet);
                    }
                }
                let query_event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
                    id: Uuid::new_v4(),
                    connection_id: c2s_connection_id,
                    sequence,
                    timestamp: Utc::now(),
                    client_addr: c2s_client_addr.clone(),
                    command: command.command_name,
                    query: command.query,
                    payload_len: packet.payload.len(),
                });
                let ownership = c2s_dependency_ownerships.get(sequence);
                if let Err(err) = record_event(&c2s_state, query_event, ownership).await {
                    c2s_dependency_ownerships.take(sequence);
                    return Err(err);
                }
                if !expects_server_response {
                    c2s_dependency_ownerships.take(sequence);
                }
            }
            upstream_write.write_all(&packet.to_wire_bytes()).await?;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_authenticated = authenticated.clone();
    let s2c_query_tracker = query_tracker.clone();
    let s2c_dependency_ownerships = dependency_ownerships.clone();
    let s2c_client_write = client_write.clone();
    let s2c_termination = termination.clone();
    let server_to_client = tokio::spawn(async move {
        let mut bytes = 0_u64;
        loop {
            let packet = match read_packet(&mut upstream_read).await {
                Ok(Some(packet)) => packet,
                Ok(None) => {
                    s2c_termination.observe_server_eof();
                    break;
                }
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    s2c_termination.observe_server_error(&error);
                    return Err(error);
                }
            };
            bytes += packet.encoded_len() as u64;
            let packet_info = parse_server_packet(&packet);
            if !s2c_authenticated.load(Ordering::SeqCst) && packet_info.kind == "ok" {
                s2c_authenticated.store(true, Ordering::SeqCst);
            }
            let mut completion = if s2c_authenticated.load(Ordering::SeqCst) {
                s2c_query_tracker
                    .lock()
                    .await
                    .observe_server_packet(&packet, packet_info)?
            } else {
                Default::default()
            };
            if s2c_termination.client_ended_first() {
                if completion.is_empty() {
                    completion = s2c_query_tracker
                        .lock()
                        .await
                        .finish_active("client_terminated")?;
                } else {
                    completion.mark_client_terminated();
                }
                record_query_completion(&s2c_state, &s2c_dependency_ownerships, completion).await?;
                break;
            }
            let write_result = s2c_client_write
                .lock()
                .await
                .write_all(&packet.to_wire_bytes())
                .await;
            match write_result {
                Ok(()) => {
                    if !completion.is_empty() {
                        record_query_completion(&s2c_state, &s2c_dependency_ownerships, completion)
                            .await?;
                    }
                }
                Err(error) if s2c_termination.observe_client_io_error(&error) => {
                    if completion.is_empty() {
                        completion = s2c_query_tracker
                            .lock()
                            .await
                            .finish_active("client_terminated")?;
                    } else {
                        completion.mark_client_terminated();
                    }
                    record_query_completion(&s2c_state, &s2c_dependency_ownerships, completion)
                        .await?;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let terminal_status = if s2c_termination.client_ended_first() {
            "client_terminated"
        } else {
            "incomplete"
        };
        let completions = s2c_query_tracker.lock().await.finish_all(terminal_status)?;
        for completion in completions {
            if !completion.is_empty() {
                record_query_completion(&s2c_state, &s2c_dependency_ownerships, completion).await?;
            }
        }
        let _ = s2c_client_write.lock().await.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let (c2s_result, s2c_result) = tokio::join!(client_to_server, server_to_client);
    let c2s_extra = c2s_result.context("client-to-server task panicked")??;
    let s2c_extra = s2c_result.context("server-to-client task panicked")??;
    client_to_server_bytes += c2s_extra;
    server_to_client_bytes += s2c_extra;

    record_connection(
        &state,
        connection_id,
        route_name,
        listen_addr,
        client_addr,
        target_host,
        target_port,
        target_addr,
        upstream_addr,
        login.username,
        login.database,
        Some(login.capability_flags),
        Some(started.elapsed().as_millis()),
        client_to_server_bytes,
        server_to_client_bytes,
        None,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn record_connection(
    state: &AppState,
    id: Uuid,
    route_name: Option<String>,
    listen_addr: String,
    client_addr: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    target_addr: Option<String>,
    upstream_addr: String,
    username: Option<String>,
    database: Option<String>,
    capability_flags: Option<u32>,
    duration_ms: Option<u128>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    error: Option<String>,
) -> Result<()> {
    record_event_and_case_dependency(
        state,
        RecorderEvent::MysqlConnection(MysqlConnectionEvent {
            id,
            timestamp: Utc::now(),
            route_name,
            listen_addr,
            client_addr,
            target_host,
            target_port,
            target_addr,
            upstream_addr,
            username,
            database,
            capability_flags,
            duration_ms,
            client_to_server_bytes,
            server_to_client_bytes,
            error,
        }),
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
