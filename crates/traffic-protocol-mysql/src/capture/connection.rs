//! MySQL recording transport, handshake, FIFO correlation and native responses.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use traffic_model::TerminationSide;
use traffic_protocol::transport::{ConnectionControl, ConnectionTermination, ObservedIo};
use uuid::Uuid;

use super::{MysqlExchangeContext, MysqlQueryTracker};
use crate::{
    MysqlPacket, MysqlSession, clear_client_compression_capability,
    clear_server_compression_capability,
    events::{MysqlConnectionEvent, MysqlQueryEvent},
    parse_client_command, parse_handshake_response, parse_server_packet, readonly_error_packet,
};

mod host;
pub use host::{CaptureDecision, CaptureHost, CaptureObservation, CaptureRequest};
#[cfg(test)]
mod tests;

trait MysqlIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> MysqlIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedMysqlIo = Box<dyn MysqlIo>;

#[derive(Debug, Clone)]
pub struct CaptureConnectionContext {
    pub route_name: Option<String>,
    pub listen_addr: String,
    pub client_addr: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub upstream_addr: String,
}

pub struct ConnectionOptions {
    pub context: CaptureConnectionContext,
    pub max_body_bytes: usize,
    pub record_raw_packets: bool,
    pub client_decoder: MysqlSession,
    pub server_decoder: MysqlSession,
    pub termination: ConnectionTermination,
}

pub async fn write_packet<W>(writer: &mut W, packet: &MysqlPacket) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    writer.write_all(&packet.to_wire_bytes()).await?;
    // TLS may retain ciphertext after write_all, even for a complete packet.
    // Delivery must not depend on the semantic tracker recognizing a response.
    writer.flush().await?;
    Ok(())
}

async fn write_rejection(
    writer: &mut (impl AsyncWrite + Unpin + ?Sized),
    request_sequence: u8,
    receipt: Box<dyn traffic_protocol::connection::CaptureOutput>,
) -> std::io::Result<()> {
    write_packet(
        writer,
        &readonly_error_packet(request_sequence.wrapping_add(1)),
    )
    .await?;
    receipt.commit();
    Ok(())
}

pub async fn run(
    client: TcpStream,
    upstream: TcpStream,
    options: ConnectionOptions,
    host: Arc<dyn CaptureHost>,
) -> Result<()> {
    let ConnectionOptions {
        context,
        max_body_bytes,
        record_raw_packets,
        mut client_decoder,
        mut server_decoder,
        termination,
    } = options;
    let client_control = ConnectionControl::new(&client)?;
    let upstream_control = ConnectionControl::new(&upstream)?;
    let mut client = ObservedIo::new(client, termination.clone(), TerminationSide::Client);
    let mut upstream = ObservedIo::new(upstream, termination.clone(), TerminationSide::Server);
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

    let mut handshake = crate::read_packet_with_session(&mut upstream, server_decoder.as_mut())
        .await
        .context("failed to read MySQL upstream handshake")?
        .context("MySQL upstream closed before handshake")?;
    // Semantic capture parses ordinary MySQL packets. Negotiate compression
    // off before either peer can switch to the seven-byte compressed header.
    clear_server_compression_capability(&mut handshake);
    server_to_client_bytes += handshake.encoded_len() as u64;
    write_packet(&mut client, &handshake)
        .await
        .context("failed to forward MySQL handshake")?;

    let mut login_packet = crate::read_packet_with_session(&mut client, client_decoder.as_mut())
        .await
        .context("failed to read MySQL login packet")?
        .context("MySQL client closed before login packet")?;
    clear_client_compression_capability(&mut login_packet);
    client_to_server_bytes += login_packet.encoded_len() as u64;
    let mut login = parse_handshake_response(&login_packet);

    let (client, upstream): (BoxedMysqlIo, BoxedMysqlIo) = if login.tls_requested {
        write_packet(&mut upstream, &login_packet)
            .await
            .context("failed to forward MySQL SSL request")?;

        let tls_host = target_host
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let downstream_config = host.server_tls_config(&tls_host)?;
        let server_name = rustls::pki_types::ServerName::try_from(tls_host.clone())
            .with_context(|| format!("invalid MySQL TLS server name {tls_host}"))?;
        let accept_downstream = async {
            TlsAcceptor::from(downstream_config)
                .accept(client)
                .await
                .context("failed to accept MySQL client TLS")
        };
        let connect_upstream = async {
            TlsConnector::from(super::upstream_client_config())
                .connect(server_name, upstream)
                .await
                .context("failed to establish MySQL upstream TLS")
        };
        let (mut client_tls, mut upstream_tls) =
            tokio::try_join!(accept_downstream, connect_upstream)?;

        let mut secure_login_packet =
            crate::read_packet_with_session(&mut client_tls, client_decoder.as_mut())
                .await
                .context("failed to read MySQL TLS login packet")?
                .context("MySQL TLS client closed before login packet")?;
        clear_client_compression_capability(&mut secure_login_packet);
        client_to_server_bytes += secure_login_packet.encoded_len() as u64;
        login = parse_handshake_response(&secure_login_packet);
        write_packet(&mut upstream_tls, &secure_login_packet)
            .await
            .context("failed to forward MySQL TLS login packet")?;
        (Box::new(client_tls), Box::new(upstream_tls))
    } else {
        write_packet(&mut upstream, &login_packet)
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
    host.observe(CaptureObservation::Connection(redacted_connection))
        .await?;

    let authenticated = Arc::new(AtomicBool::new(false));
    let query_sequence = Arc::new(AtomicU64::new(0));
    let query_tracker = Arc::new(Mutex::new(MysqlQueryTracker::new(
        max_body_bytes,
        record_raw_packets,
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
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut client_read =
        ObservedIo::new(client_read, termination.clone(), TerminationSide::Client);
    let mut upstream_read =
        ObservedIo::new(upstream_read, termination.clone(), TerminationSide::Server);
    let client_write = Arc::new(Mutex::new(client_write));

    let c2s_host = host.clone();
    let c2s_client_addr = client_addr.clone();
    let c2s_authenticated = authenticated.clone();
    let c2s_query_sequence = query_sequence.clone();
    let c2s_connection_id = connection_id;
    let c2s_query_tracker = query_tracker.clone();
    let c2s_client_write = client_write.clone();
    let c2s_username = login.username.clone();
    let c2s_termination = termination.clone();
    let client_to_server = tokio::spawn(async move {
        let mut bytes = 0_u64;
        loop {
            let before = client_read.bytes_read();
            let packet =
                match crate::read_packet_with_session(&mut client_read, client_decoder.as_mut())
                    .await
                {
                    Ok(Some(packet)) => packet,
                    Ok(None) => {
                        c2s_termination.observe_client_eof();
                        break;
                    }
                    Err(error)
                        if client_read.bytes_read() == before
                            && c2s_termination.observe_client_io_error(&error) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
            bytes += packet.encoded_len() as u64;
            let mut no_response_ownership = None;
            if c2s_authenticated.load(Ordering::SeqCst)
                && let Some(command) = parse_client_command(&packet)
            {
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
                let sequence = c2s_query_sequence.load(Ordering::SeqCst) + 1;
                let admission = c2s_host
                    .begin_request(CaptureRequest {
                        connection_id: c2s_connection_id,
                        sequence,
                        command: &command,
                        prepared_sql: prepared_sql.as_deref(),
                        database: current_database.as_deref(),
                        username: c2s_username.as_deref(),
                    })
                    .await?;
                if let CaptureDecision::Rejected(receipt) = admission {
                    write_rejection(
                        &mut *c2s_client_write.lock().await,
                        packet.sequence_id,
                        receipt,
                    )
                    .await?;
                    continue;
                }
                c2s_query_sequence.fetch_add(1, Ordering::SeqCst);
                let expects_server_response = command.expects_server_response();
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
                let query_event = CaptureObservation::Query(MysqlQueryEvent {
                    id: Uuid::new_v4(),
                    connection_id: c2s_connection_id,
                    sequence,
                    timestamp: Utc::now(),
                    client_addr: c2s_client_addr.clone(),
                    command: command.command_name,
                    query: command.query,
                    payload_len: packet.payload.len(),
                });
                c2s_host.observe(query_event).await?;
                if !expects_server_response {
                    no_response_ownership = c2s_host.take_no_response(sequence);
                }
            }
            // A command packet is a request boundary. The upstream writer may
            // be rustls, whose write completion does not imply TCP delivery.
            write_packet(&mut upstream_write, &packet).await?;
            if let Some(ownership) = no_response_ownership {
                ownership.commit();
            }
        }
        if c2s_termination
            .connection_end(TerminationSide::Client)
            .is_some()
        {
            let _ = upstream_control.reset();
        } else {
            let _ = upstream_write.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_host = host.clone();
    let s2c_authenticated = authenticated.clone();
    let s2c_query_tracker = query_tracker.clone();
    let s2c_client_write = client_write.clone();
    let s2c_termination = termination.clone();
    let server_to_client = tokio::spawn(async move {
        let result = async {
            let mut bytes = 0_u64;
            loop {
                upstream_read.begin_capture(0x00ff_ffff + 4);
                let before = upstream_read.bytes_read();
                let packet = match crate::read_packet_with_session(
                    &mut upstream_read,
                    server_decoder.as_mut(),
                )
                .await
                {
                    Ok(Some(packet)) => packet,
                    Ok(None) => {
                        s2c_termination.observe_server_eof();
                        break;
                    }
                    Err(error)
                        if upstream_read.bytes_read() == before
                            && s2c_termination
                                .observe_io_error(TerminationSide::Server, &error) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                bytes += packet.encoded_len() as u64;
                let authenticating = !s2c_authenticated.load(Ordering::SeqCst);
                if authenticating && parse_server_packet(&packet).kind == "ok" {
                    s2c_authenticated.store(true, Ordering::SeqCst);
                }
                let in_flight = s2c_query_tracker.lock().await.pending_len();
                let mut completion = if s2c_authenticated.load(Ordering::SeqCst) {
                    s2c_query_tracker
                        .lock()
                        .await
                        .observe_server_packet(&packet)?
                } else {
                    Default::default()
                };
                let output = s2c_query_tracker.lock().await.take_output();
                if s2c_termination.snapshot().is_some_and(|observed| {
                    observed.termination.side == TerminationSide::Client
                        && observed.termination.kind == traffic_model::TerminationKind::Reset
                }) {
                    if completion.is_empty() {
                        completion = s2c_query_tracker
                            .lock()
                            .await
                            .finish_active("client_terminated")?;
                    }
                    if let Some(observed) = s2c_termination.snapshot() {
                        completion.mark_terminated(observed);
                    }
                    if in_flight > 1 {
                        completion.mark_unsupported_batch();
                    }
                    s2c_host.complete(completion).await?;
                    break;
                }
                let response_complete = !completion.is_empty();
                upstream_read.begin_capture(0);
                let (write_result, receipt) = {
                    let mut client_write = s2c_client_write.lock().await;
                    use crate::response_progress::ResponseBoundary;
                    use traffic_model::trace::OutputKind;
                    let boundary = output
                        .map(|(sequence, boundary)| {
                            (
                                sequence,
                                match boundary {
                                    ResponseBoundary::Headers => OutputKind::Headers,
                                    ResponseBoundary::Row => OutputKind::Part,
                                },
                            )
                        })
                        .or_else(|| {
                            completion
                                .sequences()
                                .0
                                .map(|sequence| (sequence, OutputKind::End))
                        });
                    let receipt = boundary
                        .and_then(|(sequence, output)| s2c_host.prepare_output(sequence, output));
                    (write_packet(&mut *client_write, &packet).await, receipt)
                };
                match write_result {
                    Ok(()) => {
                        if let Some(receipt) = receipt {
                            receipt.commit();
                        }
                        if response_complete {
                            completion.mark_delivered();
                            s2c_host.complete(completion).await?;
                        } else {
                            s2c_query_tracker.lock().await.observe_delivery(&packet);
                        }
                    }
                    Err(error) if s2c_termination.observe_client_io_error(&error) => {
                        if completion.is_empty() {
                            completion = s2c_query_tracker
                                .lock()
                                .await
                                .finish_active("client_terminated")?;
                        }
                        if let Some(observed) = s2c_termination.snapshot() {
                            completion.mark_terminated(observed);
                        }
                        completion.reject_partial_write();
                        if in_flight > 1 {
                            completion.mark_unsupported_batch();
                        }
                        s2c_host.complete(completion).await?;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let terminal = s2c_termination
                .snapshot()
                .filter(|_| !s2c_termination.engine_stopped())
                .filter(|observed| observed.termination.side != TerminationSide::Engine);
            let terminal_status = terminal.map_or("incomplete", |observed| {
                if observed.termination.side == TerminationSide::Client {
                    "client_terminated"
                } else {
                    "server_terminated"
                }
            });
            let completions = s2c_query_tracker.lock().await.finish_all(terminal_status)?;
            let multiple_pending = completions.len() > 1;
            for mut completion in completions {
                if multiple_pending && terminal.is_some() {
                    completion.mark_unsupported_batch();
                }
                if s2c_termination.engine_stopped() {
                    completion.mark_engine_cleanup();
                }
                if let Some(observed) = terminal {
                    completion.mark_terminated(observed);
                }
                if !completion.is_empty() {
                    s2c_host.complete(completion).await?;
                }
            }
            Ok::<u64, anyhow::Error>(bytes)
        }
        .await;
        let capture_error = result
            .as_ref()
            .err()
            .map(|error| format!("MySQL protocol capture failed: {error:#}"));
        if capture_error.is_some() && !s2c_termination.engine_stopped() {
            let mut writer = s2c_client_write.lock().await;
            let _ = traffic_protocol::transport::forward_captured(
                &mut upstream_read,
                &mut *writer,
                &s2c_termination,
                TerminationSide::Server,
            )
            .await;
        }
        if let Some(observed) = s2c_termination
            .connection_end(TerminationSide::Server)
            .or_else(|| s2c_termination.observed(TerminationSide::Server))
        {
            match observed.termination.kind {
                traffic_model::TerminationKind::Reset => {
                    let _ = client_control.reset();
                }
                traffic_model::TerminationKind::Eof => {
                    let _ = s2c_client_write.lock().await.shutdown().await;
                }
                traffic_model::TerminationKind::Cancelled => {}
            }
        }
        if let Some(error) = capture_error
            && let Ok(completions) = s2c_query_tracker.lock().await.finish_all("incomplete")
        {
            for mut completion in completions {
                completion.mark_capture_error(&error);
                let _ = s2c_host.complete(completion).await;
            }
        }
        result
    });

    let (c2s_result, s2c_result) = tokio::join!(client_to_server, server_to_client);
    let c2s_extra = c2s_result.context("client-to-server task panicked")??;
    let s2c_extra = s2c_result.context("server-to-client task panicked")??;
    client_to_server_bytes += c2s_extra;
    server_to_client_bytes += s2c_extra;

    // A server FIN leaves the Source write direction open. Calls arriving after
    // the response task ended have no exchange-relative termination evidence.
    for mut completion in query_tracker.lock().await.finish_all("incomplete")? {
        completion.mark_capture_error("MySQL request began after the response direction ended; post-terminal capture is unsupported");
        host.complete(completion).await?;
    }

    record_connection(
        host.as_ref(),
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
    host: &dyn CaptureHost,
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
    host.observe(CaptureObservation::Connection(MysqlConnectionEvent {
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
    }))
    .await
}
