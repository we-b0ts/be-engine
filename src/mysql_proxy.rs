use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use crate::AppState;
use crate::MysqlRouteConfig;
use crate::mysql_protocol::{
    MysqlPacket, ServerPacketInfo, parse_client_command, parse_handshake_response,
    parse_server_packet, read_packet,
};
use crate::mysql_semantic::{MysqlExchangeContext, MysqlSemanticTracker};
use crate::recorder::{
    MysqlConnectionEvent, MysqlQueryEvent, MysqlResponseEvent, MysqlResponsePacket,
    MysqlTlsRejectedEvent, ProcessInfo, ProxyErrorEvent, RecorderEvent, capture_body,
    capture_body_with_original_len,
};

#[derive(Debug, Clone)]
pub(crate) struct MysqlConnectionContext {
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub client_process: Option<ProcessInfo>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub upstream_addr: String,
}

struct MysqlResponseTracker {
    active: Option<MysqlResponseBuilder>,
    max_payload_bytes: usize,
    record_raw_packets: bool,
}

struct MysqlResponseBuilder {
    connection_id: Uuid,
    query_sequence: u64,
    client_addr: Option<String>,
    client_process: Option<ProcessInfo>,
    command: String,
    started: Instant,
    status: String,
    phase: MysqlResponsePhase,
    packet_count: usize,
    packets: Vec<MysqlResponsePacket>,
    payload: Vec<u8>,
    payload_bytes: usize,
    error_code: Option<u16>,
    error_message: Option<String>,
    record_raw_packets: bool,
}

#[derive(Debug, Clone, Copy)]
enum MysqlResponsePhase {
    FirstPacket,
    ResultSet { eof_count: u8 },
    StmtPrepare { eof_count: u8, eof_needed: u8 },
}

impl MysqlResponseTracker {
    fn new(max_payload_bytes: usize, record_raw_packets: bool) -> Self {
        Self {
            active: None,
            max_payload_bytes,
            record_raw_packets,
        }
    }

    fn start_query(
        &mut self,
        connection_id: Uuid,
        query_sequence: u64,
        command: String,
        client_addr: Option<String>,
        client_process: Option<ProcessInfo>,
    ) -> Option<MysqlResponseEvent> {
        let previous = self.finish_active("incomplete");
        self.active = Some(MysqlResponseBuilder {
            connection_id,
            query_sequence,
            client_addr,
            client_process,
            command,
            started: Instant::now(),
            status: "pending".to_string(),
            phase: MysqlResponsePhase::FirstPacket,
            packet_count: 0,
            packets: Vec::new(),
            payload: Vec::new(),
            payload_bytes: 0,
            error_code: None,
            error_message: None,
            record_raw_packets: self.record_raw_packets,
        });
        previous
    }

    fn observe_packet(
        &mut self,
        packet: &MysqlPacket,
        info: ServerPacketInfo,
    ) -> Option<MysqlResponseEvent> {
        let active = self.active.as_mut()?;
        let complete = active.observe_packet(packet, info, self.max_payload_bytes);
        complete.then(|| self.finish_active("incomplete")).flatten()
    }

    fn finish_active(&mut self, fallback_status: &str) -> Option<MysqlResponseEvent> {
        self.active
            .take()
            .map(|mut active| active.finish(fallback_status))
    }
}

impl MysqlResponseBuilder {
    fn observe_packet(
        &mut self,
        packet: &MysqlPacket,
        info: ServerPacketInfo,
        max_payload_bytes: usize,
    ) -> bool {
        self.payload_bytes += packet.payload.len();
        self.packet_count += 1;
        if self.payload.len() < max_payload_bytes {
            let remaining = max_payload_bytes - self.payload.len();
            self.payload
                .extend_from_slice(&packet.payload[..packet.payload.len().min(remaining)]);
        }
        self.error_code = self.error_code.or(info.error_code);
        if self.error_message.is_none() {
            self.error_message = info.error_message.clone();
        }

        let packet_kind = response_packet_kind(self.phase, &info);
        if self.record_raw_packets {
            self.packets.push(MysqlResponsePacket {
                sequence_id: packet.sequence_id,
                packet_kind,
                payload_len: packet.payload.len(),
                payload: capture_body(&packet.payload, max_payload_bytes),
            });
        }

        if info.kind == "error" {
            self.status = "error".to_string();
            return true;
        }

        match self.phase {
            MysqlResponsePhase::FirstPacket => self.observe_first_packet(packet, &info),
            MysqlResponsePhase::ResultSet { eof_count } => {
                if info.kind == "eof" {
                    let eof_count = eof_count + 1;
                    if eof_count >= 2 {
                        self.status = "resultset".to_string();
                        true
                    } else {
                        self.phase = MysqlResponsePhase::ResultSet { eof_count };
                        false
                    }
                } else {
                    false
                }
            }
            MysqlResponsePhase::StmtPrepare {
                eof_count,
                eof_needed,
            } => {
                if info.kind == "eof" {
                    let eof_count = eof_count + 1;
                    if eof_count >= eof_needed {
                        self.status = "stmt_prepare".to_string();
                        true
                    } else {
                        self.phase = MysqlResponsePhase::StmtPrepare {
                            eof_count,
                            eof_needed,
                        };
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    fn observe_first_packet(&mut self, packet: &MysqlPacket, info: &ServerPacketInfo) -> bool {
        if self.command == "COM_STMT_PREPARE" && info.kind == "ok" {
            let eof_needed = parse_stmt_prepare_eof_count(&packet.payload);
            if eof_needed == 0 {
                self.status = "stmt_prepare".to_string();
                true
            } else {
                self.status = "stmt_prepare".to_string();
                self.phase = MysqlResponsePhase::StmtPrepare {
                    eof_count: 0,
                    eof_needed,
                };
                false
            }
        } else if info.kind == "ok" {
            self.status = "ok".to_string();
            true
        } else if info.kind == "eof" {
            self.status = "eof".to_string();
            true
        } else {
            self.status = "resultset".to_string();
            self.phase = MysqlResponsePhase::ResultSet { eof_count: 0 };
            false
        }
    }

    fn finish(&mut self, fallback_status: &str) -> MysqlResponseEvent {
        let status = if self.status == "pending" {
            fallback_status.to_string()
        } else {
            self.status.clone()
        };
        MysqlResponseEvent {
            id: Uuid::new_v4(),
            connection_id: self.connection_id,
            query_sequence: self.query_sequence,
            timestamp: Utc::now(),
            client_addr: self.client_addr.clone(),
            client_process: self.client_process.clone(),
            status,
            packet_count: self.packet_count,
            payload_bytes: self.payload_bytes,
            duration_ms: self.started.elapsed().as_millis(),
            error_code: self.error_code,
            error_message: self.error_message.clone(),
            payload: capture_body_with_original_len(&self.payload, self.payload_bytes),
            packets: self
                .record_raw_packets
                .then(|| std::mem::take(&mut self.packets)),
        }
    }
}

fn response_packet_kind(phase: MysqlResponsePhase, info: &ServerPacketInfo) -> String {
    if matches!(phase, MysqlResponsePhase::ResultSet { .. }) && info.kind == "ok" {
        "result_or_data".to_string()
    } else {
        info.kind.clone()
    }
}

fn parse_stmt_prepare_eof_count(payload: &[u8]) -> u8 {
    if payload.len() < 9 || payload.first() != Some(&0x00) {
        return 0;
    }
    let num_columns = u16::from_le_bytes([payload[5], payload[6]]);
    let num_params = u16::from_le_bytes([payload[7], payload[8]]);
    u8::from(num_params > 0) + u8::from(num_columns > 0)
}

pub async fn run(state: AppState) -> Result<()> {
    let routes = state.config().mysql.effective_routes();
    let mut tasks = JoinSet::new();

    for route in routes {
        let state = state.clone();
        tasks.spawn(async move { run_route(state, route).await });
    }

    match tasks.join_next().await {
        Some(result) => result.context("MySQL route task panicked")?,
        None => Ok(()),
    }
}

async fn run_route(state: AppState, route: MysqlRouteConfig) -> Result<()> {
    let listener = TcpListener::bind(route.listen)
        .await
        .with_context(|| format!("failed to bind MySQL proxy {}", route.listen))?;
    info!(
        route = route.name.as_deref().unwrap_or("unnamed"),
        listen = %route.listen,
        upstream = %route.upstream,
        "MySQL proxy listening"
    );

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
                client_process: None,
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
                    timestamp: Utc::now(),
                    protocol: "mysql".to_string(),
                    client_addr: context.client_addr.clone(),
                    client_process: context.client_process.clone(),
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
    let connection_id = Uuid::new_v4();
    let started = Instant::now();
    let route_name = context.route_name.clone();
    let listen_addr = context.listen_addr.clone();
    let client_addr = context.client_addr.clone();
    let client_process = context.client_process.clone();
    let target_host = context.target_host.clone();
    let target_port = context.target_port;
    let target_addr = context.target_addr.clone();
    let upstream_addr = context.upstream_addr.clone();

    let mut server_to_client_bytes = 0_u64;
    let mut client_to_server_bytes = 0_u64;

    let handshake = read_packet(&mut upstream)
        .await
        .context("failed to read MySQL upstream handshake")?
        .context("MySQL upstream closed before handshake")?;
    server_to_client_bytes += handshake.encoded_len() as u64;
    client
        .write_all(&handshake.to_wire_bytes())
        .await
        .context("failed to forward MySQL handshake")?;

    let login_packet = read_packet(&mut client)
        .await
        .context("failed to read MySQL login packet")?
        .context("MySQL client closed before login packet")?;
    client_to_server_bytes += login_packet.encoded_len() as u64;
    let login = parse_handshake_response(&login_packet);

    if login.tls_requested {
        let event = MysqlTlsRejectedEvent {
            id: Uuid::new_v4(),
            connection_id,
            timestamp: Utc::now(),
            route_name: route_name.clone(),
            listen_addr: listen_addr.clone(),
            client_addr: client_addr.clone(),
            client_process: client_process.clone(),
            upstream_addr: upstream_addr.clone(),
            target_host: target_host.clone(),
            target_port,
            target_addr: target_addr.clone(),
            capability_flags: login.capability_flags,
            reason: "MySQL TLS is detected but not implemented in v1".to_string(),
        };
        record_event_and_case_dependency(&state, RecorderEvent::MysqlTlsRejected(event)).await?;
        record_connection(
            &state,
            connection_id,
            route_name,
            listen_addr,
            client_addr,
            client_process,
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
            Some("MySQL TLS requested and rejected".to_string()),
        )
        .await?;
        return Ok(());
    }

    upstream
        .write_all(&login_packet.to_wire_bytes())
        .await
        .context("failed to forward MySQL login packet")?;

    let redacted_connection = MysqlConnectionEvent {
        id: connection_id,
        timestamp: Utc::now(),
        route_name: route_name.clone(),
        listen_addr: listen_addr.clone(),
        client_addr: client_addr.clone(),
        client_process: client_process.clone(),
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
    let response_tracker = Arc::new(Mutex::new(MysqlResponseTracker::new(
        state.config().recording.max_body_bytes,
        state.config().mysql.record_raw_packets,
    )));
    let semantic_tracker = Arc::new(Mutex::new(MysqlSemanticTracker::new(
        state.config().recording.max_body_bytes,
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
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let c2s_state = state.clone();
    let c2s_client_addr = client_addr.clone();
    let c2s_client_process = client_process.clone();
    let c2s_authenticated = authenticated.clone();
    let c2s_query_sequence = query_sequence.clone();
    let c2s_connection_id = connection_id;
    let c2s_response_tracker = response_tracker.clone();
    let c2s_semantic_tracker = semantic_tracker.clone();
    let client_to_server = tokio::spawn(async move {
        let mut bytes = 0_u64;
        loop {
            let packet = match read_packet(&mut client_read).await? {
                Some(packet) => packet,
                None => break,
            };
            bytes += packet.encoded_len() as u64;
            if c2s_authenticated.load(Ordering::SeqCst)
                && let Some(command) = parse_client_command(&packet)
            {
                let sequence = c2s_query_sequence.fetch_add(1, Ordering::SeqCst) + 1;
                let flushed_response = {
                    let mut tracker = c2s_response_tracker.lock().await;
                    tracker.start_query(
                        c2s_connection_id,
                        sequence,
                        command.command_name.clone(),
                        c2s_client_addr.clone(),
                        c2s_client_process.clone(),
                    )
                };
                let flushed_exchange = {
                    let mut tracker = c2s_semantic_tracker.lock().await;
                    if command.command_name == "COM_INIT_DB" {
                        tracker.set_database(command.query.clone());
                    }
                    tracker.start_query(
                        c2s_connection_id,
                        sequence,
                        &command,
                        &packet,
                        c2s_client_addr.clone(),
                        c2s_client_process.clone(),
                    )
                };
                if let Some(response) = flushed_response {
                    record_event_and_case_dependency(
                        &c2s_state,
                        RecorderEvent::MysqlResponse(response),
                    )
                    .await?;
                }
                if let Some(exchange) = flushed_exchange {
                    record_event_and_case_dependency(
                        &c2s_state,
                        RecorderEvent::MysqlExchange(exchange),
                    )
                    .await?;
                }
                record_event_and_case_dependency(
                    &c2s_state,
                    RecorderEvent::MysqlQuery(MysqlQueryEvent {
                        id: Uuid::new_v4(),
                        connection_id: c2s_connection_id,
                        sequence,
                        timestamp: Utc::now(),
                        client_addr: c2s_client_addr.clone(),
                        client_process: c2s_client_process.clone(),
                        command: command.command_name,
                        query: command.query,
                        payload_len: packet.payload.len(),
                    }),
                )
                .await?;
            }
            upstream_write.write_all(&packet.to_wire_bytes()).await?;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_authenticated = authenticated.clone();
    let s2c_response_tracker = response_tracker.clone();
    let s2c_semantic_tracker = semantic_tracker.clone();
    let server_to_client = tokio::spawn(async move {
        let mut bytes = 0_u64;
        loop {
            let packet = match read_packet(&mut upstream_read).await? {
                Some(packet) => packet,
                None => break,
            };
            bytes += packet.encoded_len() as u64;
            let packet_info = parse_server_packet(&packet);
            if !s2c_authenticated.load(Ordering::SeqCst) && packet_info.kind == "ok" {
                s2c_authenticated.store(true, Ordering::SeqCst);
            }
            if s2c_authenticated.load(Ordering::SeqCst) {
                {
                    let mut tracker = s2c_semantic_tracker.lock().await;
                    tracker.observe_packet(&packet);
                }
                let response = {
                    let mut tracker = s2c_response_tracker.lock().await;
                    tracker.observe_packet(&packet, packet_info)
                };
                if let Some(response) = response {
                    let exchange = {
                        let mut tracker = s2c_semantic_tracker.lock().await;
                        tracker.finish_from_response(&response)
                    };
                    record_event_and_case_dependency(
                        &s2c_state,
                        RecorderEvent::MysqlResponse(response),
                    )
                    .await?;
                    if let Some(exchange) = exchange {
                        record_event_and_case_dependency(
                            &s2c_state,
                            RecorderEvent::MysqlExchange(exchange),
                        )
                        .await?;
                    }
                }
            }
            client_write.write_all(&packet.to_wire_bytes()).await?;
        }
        let response = {
            let mut tracker = s2c_response_tracker.lock().await;
            tracker.finish_active("incomplete")
        };
        if let Some(response) = response {
            let exchange = {
                let mut tracker = s2c_semantic_tracker.lock().await;
                tracker.finish_from_response(&response)
            };
            record_event_and_case_dependency(&s2c_state, RecorderEvent::MysqlResponse(response))
                .await?;
            if let Some(exchange) = exchange {
                record_event_and_case_dependency(
                    &s2c_state,
                    RecorderEvent::MysqlExchange(exchange),
                )
                .await?;
            }
        } else {
            let exchange = {
                let mut tracker = s2c_semantic_tracker.lock().await;
                tracker.finish_active("incomplete", None, None, None)
            };
            if let Some(exchange) = exchange {
                record_event_and_case_dependency(
                    &s2c_state,
                    RecorderEvent::MysqlExchange(exchange),
                )
                .await?;
            }
        }
        let _ = client_write.shutdown().await;
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
        client_process,
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
    client_process: Option<ProcessInfo>,
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
            client_process,
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
    state.recorder().record(event.clone()).await?;
    state.record_dependency_if_relevant(&event).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_resultset_packets_into_one_response() {
        let mut tracker = MysqlResponseTracker::new(1024, true);
        tracker.start_query(Uuid::nil(), 7, "COM_STMT_EXECUTE".to_string(), None, None);

        assert!(
            observe_payload(&mut tracker, 1, &[1]).is_none(),
            "column-count packet should not finish the response"
        );
        assert!(
            observe_payload(&mut tracker, 2, b"column").is_none(),
            "column definition packet should not finish the response"
        );
        assert!(
            observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none(),
            "first EOF ends column definitions only"
        );
        assert!(
            observe_payload(&mut tracker, 4, &[0x00, b'r', b'o', b'w']).is_none(),
            "binary row payloads may start with 0x00 and must not finish as OK"
        );

        let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
            .expect("second EOF should finish the response");
        assert_eq!(response.query_sequence, 7);
        assert_eq!(response.status, "resultset");
        assert_eq!(response.packet_count, 5);
        assert_eq!(response.payload_bytes, 21);
        assert_eq!(response.payload.original_len, 21);
        assert_eq!(response.payload.stored_len, 21);
        assert!(!response.payload.truncated);
        let packets = response.packets.expect("raw packets should be recorded");
        assert_eq!(packets[3].packet_kind, "result_or_data");
        assert_eq!(packets[3].payload.original_len, 4);
    }

    #[test]
    fn response_payload_is_concatenated_and_truncated() {
        let mut tracker = MysqlResponseTracker::new(4, false);
        tracker.start_query(Uuid::nil(), 8, "COM_STMT_EXECUTE".to_string(), None, None);

        assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
        assert!(observe_payload(&mut tracker, 2, b"abc").is_none());
        assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
        assert!(observe_payload(&mut tracker, 4, b"row").is_none());
        let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

        assert_eq!(response.payload_bytes, 17);
        assert_eq!(response.payload.original_len, 17);
        assert_eq!(response.payload.stored_len, 4);
        assert!(response.payload.truncated);
        assert!(response.packets.is_none());
    }

    #[test]
    fn raw_packets_can_be_recorded_when_enabled() {
        let mut tracker = MysqlResponseTracker::new(4, true);
        tracker.start_query(Uuid::nil(), 9, "COM_STMT_EXECUTE".to_string(), None, None);

        assert!(observe_payload(&mut tracker, 1, &[1]).is_none());
        assert!(observe_payload(&mut tracker, 2, b"abcdef").is_none());
        assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
        assert!(observe_payload(&mut tracker, 4, b"row").is_none());
        let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0]).unwrap();

        let packets = response.packets.expect("raw packets should be recorded");
        assert_eq!(packets[1].payload_len, 6);
        assert_eq!(packets[1].payload.original_len, 6);
        assert_eq!(packets[1].payload.stored_len, 4);
        assert!(packets[1].payload.truncated);
    }

    #[test]
    fn aggregates_stmt_prepare_until_expected_eofs() {
        let mut tracker = MysqlResponseTracker::new(1024, false);
        tracker.start_query(Uuid::nil(), 3, "COM_STMT_PREPARE".to_string(), None, None);

        let mut prepare_ok = vec![0x00];
        prepare_ok.extend_from_slice(&1_u32.to_le_bytes());
        prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
        prepare_ok.extend_from_slice(&1_u16.to_le_bytes());
        prepare_ok.push(0);
        prepare_ok.extend_from_slice(&0_u16.to_le_bytes());

        assert!(observe_payload(&mut tracker, 1, &prepare_ok).is_none());
        assert!(observe_payload(&mut tracker, 2, b"param").is_none());
        assert!(observe_payload(&mut tracker, 3, &[0xfe, 0, 0, 0, 0]).is_none());
        assert!(observe_payload(&mut tracker, 4, b"column").is_none());
        let response = observe_payload(&mut tracker, 5, &[0xfe, 0, 0, 0, 0])
            .expect("stmt prepare should finish after param and column EOF packets");
        assert_eq!(response.status, "stmt_prepare");
        assert_eq!(response.packet_count, 5);
        assert!(response.packets.is_none());
    }

    fn observe_payload(
        tracker: &mut MysqlResponseTracker,
        sequence_id: u8,
        payload: &[u8],
    ) -> Option<MysqlResponseEvent> {
        let packet = MysqlPacket {
            sequence_id,
            payload: payload.to_vec(),
        };
        let info = parse_server_packet(&packet);
        tracker.observe_packet(&packet, info)
    }
}
