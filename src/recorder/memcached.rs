use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

use crate::AppState;
use crate::DependencyExchangeOutcome;
use crate::access_policy::AccessDecision;
use crate::dependency::TerminationSide;
use crate::dependency::termination::{
    ConnectionControl, ConnectionTermination, ObservedIo, ObservedTermination,
};
use crate::memcached::access::classify_request;
use crate::memcached::{
    BinaryFrame, BufferedReader, MemcachedRequest, MemcachedWireProtocol,
    binary_access_denied_response, binary_response_is_complete, read_binary_frame,
    read_text_request, read_text_response,
};
use crate::recorder::capture_health::{ConnectionCaptureHealth, RawTrafficDirection};

mod fallback;
mod recording;
#[cfg(test)]
mod tests;

use fallback::forward_buffer_and_copy;
use recording::{finish_pending, record_connection, record_exchange};

#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) upstream_addr: String,
}

#[derive(Debug)]
struct PendingMemcachedExchange {
    targets: crate::active_case::DependencyTargets,
    sequence: u64,
    request: MemcachedRequest,
    response_frames: Vec<Vec<u8>>,
    response_frame_offsets_ms: Vec<u128>,
    replay_safe: bool,
    warnings: Vec<String>,
    started: Instant,
    request_started_at: chrono::DateTime<chrono::Utc>,
    termination: Option<ObservedTermination>,
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let termination = ConnectionTermination::default();
    let _connection = state.dependency_connections().register_observed(
        "memcached",
        &[&client, &upstream],
        &termination,
    )?;
    let started = Instant::now();
    record_connection(
        &state,
        connection_id,
        &context,
        wire_protocol,
        "opened",
        None,
        0,
        0,
        true,
        None,
    )
    .await?;
    let result = match wire_protocol {
        MemcachedWireProtocol::Text => {
            proxy_text(
                client,
                upstream,
                state.clone(),
                context.clone(),
                connection_id,
                termination,
            )
            .await
        }
        MemcachedWireProtocol::Binary => {
            proxy_binary(
                client,
                upstream,
                state.clone(),
                context.clone(),
                connection_id,
                termination,
            )
            .await
        }
    };
    let (client_bytes, server_bytes, replay_safe, error) = match result {
        Ok(result) => (result.0, result.1, result.2, None),
        Err(err) => (0, 0, false, Some(err.to_string())),
    };
    record_connection(
        &state,
        connection_id,
        &context,
        wire_protocol,
        "closed",
        Some(started.elapsed().as_millis()),
        client_bytes,
        server_bytes,
        replay_safe,
        error.clone(),
    )
    .await?;
    if let Some(error) = error {
        return Err(anyhow!(error));
    }
    Ok(())
}

async fn proxy_text(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
    connection_id: Uuid,
    termination: ConnectionTermination,
) -> Result<(u64, u64, bool)> {
    let max_frame_bytes = state.config().recording.max_body_bytes;
    let pending = Arc::new(Mutex::new(VecDeque::<PendingMemcachedExchange>::new()));
    let capture_health = Arc::new(ConnectionCaptureHealth::new(
        connection_id,
        "memcached",
        context.client_addr.clone(),
        context.target_addr.clone(),
    ));
    let client_control = ConnectionControl::new(&client)?;
    let upstream_control = ConnectionControl::new(&upstream)?;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let pending_drained = Arc::new(Notify::new());
    let c2s_state = state.clone();
    let c2s_context = context.clone();
    let c2s_pending = pending.clone();
    let c2s_capture_health = capture_health.clone();
    let c2s_client_write = client_write.clone();
    let c2s_pending_drained = pending_drained.clone();
    let c2s_termination = termination.clone();
    let c2s_upstream_control = upstream_control.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::new(
            ObservedIo::new(
                client_read,
                c2s_termination.clone(),
                TerminationSide::Client,
            ),
            max_frame_bytes,
        );
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    None,
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            let request = match read_text_request(&mut reader).await {
                Ok(Some(request)) => request,
                Ok(None) => {
                    c2s_termination.observe_client_eof();
                    break;
                }
                Err(error) => {
                    if reader.buffer.is_empty() && c2s_termination.observe_client_error(&error) {
                        break;
                    }
                    c2s_capture_health.activate(
                        &c2s_state,
                        format!(
                            "Memcached text request parse failed; switched to raw forwarding: {error}"
                        ),
                    );
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        None,
                        &c2s_capture_health,
                        &c2s_state,
                        RawTrafficDirection::ClientToServer,
                    )
                    .await?;
                    break;
                }
            };
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    Some(&request.raw),
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            sequence += 1;
            let operation_class = classify_request(&request);
            if c2s_state.access_decision(operation_class) == AccessDecision::Reject {
                c2s_state
                    .record_readonly_rejection(
                        "memcached",
                        operation_class,
                        request.command.clone(),
                        c2s_context.client_addr.clone(),
                        Some(c2s_context.target_addr.clone()),
                        "Memcached command is classified as a write operation",
                    )
                    .await;
                loop {
                    let notified = c2s_pending_drained.notified();
                    if c2s_pending.lock().await.is_empty() {
                        break;
                    }
                    notified.await;
                }
                if !request.noreply {
                    c2s_client_write
                        .lock()
                        .await
                        .write_all(b"CLIENT_ERROR request blocked by recording access policy\r\n")
                        .await?;
                }
                bytes += request.raw.len() as u64;
                continue;
            }
            let no_response = request.noreply || request.command == "quit";
            let replay_safe = !is_meta_command(&request.command);
            let warnings = if replay_safe {
                Vec::new()
            } else {
                vec!["Memcached Meta Text is unsupported".to_string()]
            };
            let pending_exchange = PendingMemcachedExchange {
                targets: c2s_state.capture_memcached_dependency(
                    connection_id,
                    sequence,
                    c2s_context.target_port,
                    &request.command,
                    request.key.as_deref(),
                ),
                sequence,
                request,
                response_frames: Vec::new(),
                response_frame_offsets_ms: Vec::new(),
                replay_safe,
                warnings,
                started: Instant::now(),
                request_started_at: chrono::Utc::now(),
                termination: None,
            };
            if no_response {
                upstream_write
                    .write_all(&pending_exchange.request.raw)
                    .await?;
                bytes += pending_exchange.request.raw.len() as u64;
                record_exchange(
                    &c2s_state,
                    connection_id,
                    &c2s_context,
                    MemcachedWireProtocol::Text,
                    pending_exchange,
                    true,
                    DependencyExchangeOutcome::NoResponse,
                    max_frame_bytes,
                )
                .await?;
            } else {
                let raw = pending_exchange.request.raw.clone();
                c2s_pending.lock().await.push_back(pending_exchange);
                upstream_write.write_all(&raw).await?;
                bytes += raw.len() as u64;
            }
        }
        if c2s_termination
            .connection_end(TerminationSide::Client)
            .is_some()
        {
            let _ = c2s_upstream_control.reset();
        } else {
            let _ = upstream_write.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_context = context.clone();
    let s2c_pending = pending.clone();
    let s2c_capture_health = capture_health.clone();
    let s2c_client_write = client_write.clone();
    let s2c_pending_drained = pending_drained.clone();
    let s2c_termination = termination.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::new(
            ObservedIo::new(
                upstream_read,
                s2c_termination.clone(),
                TerminationSide::Server,
            ),
            max_frame_bytes,
        );
        let mut bytes = 0_u64;
        loop {
            let command = {
                let pending = s2c_pending.lock().await;
                pending
                    .front()
                    .map(|exchange| exchange.request.command.clone())
            };
            let Some(command) = command else {
                if reader.inner.get_ref().readable().await.is_err() {
                    break;
                }
                if !s2c_pending.lock().await.is_empty() {
                    continue;
                }
                if s2c_capture_health.is_degraded() {
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        None,
                        &s2c_capture_health,
                        &s2c_state,
                        RawTrafficDirection::ServerToClient,
                    )
                    .await?;
                    break;
                }
                let mut probe = [0_u8; 1];
                match reader.inner.get_mut().peek(&mut probe).await {
                    Ok(0) => {
                        s2c_termination.observe_server_eof();
                        break;
                    }
                    Ok(_) => {
                        // `peek` may wait after the empty-queue check above.
                        // The client task always queues a response-bearing
                        // request before writing it upstream, so a request can
                        // legitimately appear while this task is waiting for
                        // the corresponding response bytes. Recheck here
                        // before classifying those bytes as unsolicited.
                        if !s2c_pending.lock().await.is_empty() {
                            continue;
                        }
                        s2c_capture_health.activate(
                            &s2c_state,
                            "Memcached text response has no pending request; switched to raw forwarding"
                                .to_string(),
                        );
                        let mut writer = s2c_client_write.lock().await;
                        bytes += forward_buffer_and_copy(
                            &mut reader,
                            &mut *writer,
                            None,
                            &s2c_capture_health,
                            &s2c_state,
                            RawTrafficDirection::ServerToClient,
                        )
                        .await?;
                        break;
                    }
                    Err(err) => {
                        let error = anyhow::Error::from(err);
                        s2c_termination.observe_server_error(&error);
                        return Err(error);
                    }
                }
            };
            let response = match read_text_response(&mut reader, &command).await {
                Ok(Some(response)) => response,
                Ok(None) => {
                    s2c_termination.observe_server_eof();
                    break;
                }
                Err(error)
                    if reader.buffer.is_empty() && s2c_termination.observe_server_error(&error) =>
                {
                    break;
                }
                Err(error) => {
                    s2c_capture_health.activate(
                        &s2c_state,
                        format!(
                            "Memcached text response parse failed; switched to raw forwarding: {error}"
                        ),
                    );
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        None,
                        &s2c_capture_health,
                        &s2c_state,
                        RawTrafficDirection::ServerToClient,
                    )
                    .await?;
                    break;
                }
            };
            if s2c_capture_health.is_degraded() {
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&response),
                    &s2c_capture_health,
                    &s2c_state,
                    RawTrafficDirection::ServerToClient,
                )
                .await?;
                break;
            }
            let mut exchange = s2c_pending
                .lock()
                .await
                .pop_front()
                .expect("pending Memcached text request");
            s2c_pending_drained.notify_waiters();
            exchange.response_frames.push(response.to_vec());
            if s2c_termination.snapshot().is_some_and(|observed| {
                observed.termination.side == TerminationSide::Client
                    && observed.termination.kind == crate::dependency::TerminationKind::Reset
            }) {
                exchange.response_frames.pop();
                exchange.termination = s2c_termination.snapshot();
                if !s2c_pending.lock().await.is_empty() {
                    exchange.replay_safe = false;
                    exchange.warnings.push("multiple in-flight Memcached requests share a termination; batch replay is unsupported".into());
                }
                record_exchange(
                    &s2c_state,
                    connection_id,
                    &s2c_context,
                    MemcachedWireProtocol::Text,
                    exchange,
                    false,
                    DependencyExchangeOutcome::ClientTerminated,
                    max_frame_bytes,
                )
                .await?;
                break;
            }
            match s2c_client_write.lock().await.write_all(&response).await {
                Ok(()) => {
                    bytes += response.len() as u64;
                    exchange
                        .response_frame_offsets_ms
                        .push(exchange.started.elapsed().as_millis());
                    record_exchange(
                        &s2c_state,
                        connection_id,
                        &s2c_context,
                        MemcachedWireProtocol::Text,
                        exchange,
                        false,
                        DependencyExchangeOutcome::Response,
                        max_frame_bytes,
                    )
                    .await?;
                }
                Err(error) if s2c_termination.observe_client_io_error(&error) => {
                    if let Some(observed) = s2c_termination.snapshot() {
                        exchange.termination = Some(observed);
                    }
                    exchange.replay_safe = false;
                    exchange
                        .warnings
                        .push("response write failed after an unknown delivery prefix".into());
                    exchange.response_frames.pop();
                    exchange.termination = s2c_termination.snapshot();
                    record_exchange(
                        &s2c_state,
                        connection_id,
                        &s2c_context,
                        MemcachedWireProtocol::Text,
                        exchange,
                        false,
                        DependencyExchangeOutcome::ClientTerminated,
                        max_frame_bytes,
                    )
                    .await?;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if s2c_termination
            .connection_end(TerminationSide::Server)
            .is_some()
        {
            let _ = client_control.reset();
        } else {
            let _ = s2c_client_write.lock().await.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let (c2s_result, s2c_result) = tokio::join!(c2s, s2c);
    let c2s_bytes = c2s_result.context("Memcached text client task panicked")??;
    let s2c_bytes = s2c_result.context("Memcached text server task panicked")??;
    let mut replay_safe = finish_pending(
        &state,
        connection_id,
        &context,
        MemcachedWireProtocol::Text,
        &pending,
        &termination,
        max_frame_bytes,
    )
    .await?;
    if capture_health.is_degraded() {
        replay_safe = false;
    }
    Ok((c2s_bytes, s2c_bytes, replay_safe))
}

async fn proxy_binary(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
    connection_id: Uuid,
    termination: ConnectionTermination,
) -> Result<(u64, u64, bool)> {
    let max_frame_bytes = state.config().recording.max_body_bytes;
    let pending = Arc::new(Mutex::new(VecDeque::<PendingMemcachedExchange>::new()));
    let capture_health = Arc::new(ConnectionCaptureHealth::new(
        connection_id,
        "memcached",
        context.client_addr.clone(),
        context.target_addr.clone(),
    ));
    let client_control = ConnectionControl::new(&client)?;
    let upstream_control = ConnectionControl::new(&upstream)?;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let c2s_pending = pending.clone();
    let c2s_capture_health = capture_health.clone();
    let c2s_state = state.clone();
    let c2s_context = context.clone();
    let c2s_client_write = client_write.clone();
    let c2s_termination = termination.clone();
    let c2s_upstream_control = upstream_control.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::new(
            ObservedIo::new(
                client_read,
                c2s_termination.clone(),
                TerminationSide::Client,
            ),
            max_frame_bytes,
        );
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    None,
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            let frame = match read_binary_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    c2s_termination.observe_client_eof();
                    break;
                }
                Err(error) => {
                    if reader.buffer.is_empty() && c2s_termination.observe_client_error(&error) {
                        break;
                    }
                    c2s_capture_health.activate(
                        &c2s_state,
                        format!(
                            "Memcached binary request parse failed; switched to raw forwarding: {error}"
                        ),
                    );
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        None,
                        &c2s_capture_health,
                        &c2s_state,
                        RawTrafficDirection::ClientToServer,
                    )
                    .await?;
                    break;
                }
            };
            if c2s_capture_health.is_degraded() {
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut upstream_write,
                    Some(&frame.raw),
                    &c2s_capture_health,
                    &c2s_state,
                    RawTrafficDirection::ClientToServer,
                )
                .await?;
                break;
            }
            let mut request = match frame.as_request() {
                Ok(request) => request,
                Err(error) => {
                    c2s_capture_health.activate(
                        &c2s_state,
                        format!(
                            "Memcached binary request validation failed; switched to raw forwarding: {error}"
                        ),
                    );
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut upstream_write,
                        Some(&frame.raw),
                        &c2s_capture_health,
                        &c2s_state,
                        RawTrafficDirection::ClientToServer,
                    )
                    .await?;
                    break;
                }
            };
            sequence += 1;
            let operation_class = classify_request(&request);
            if c2s_state.access_decision(operation_class) == AccessDecision::Reject {
                c2s_state
                    .record_readonly_rejection(
                        "memcached",
                        operation_class,
                        request.command.clone(),
                        c2s_context.client_addr.clone(),
                        Some(c2s_context.target_addr.clone()),
                        "Memcached command is classified as a write operation",
                    )
                    .await;
                c2s_client_write
                    .lock()
                    .await
                    .write_all(&binary_access_denied_response(&frame))
                    .await?;
                bytes += frame.raw.len() as u64;
                continue;
            }
            let sasl = matches!(frame.opcode, 0x20..=0x22);
            let unknown = request.command == "unknown";
            let warnings = if unknown {
                vec![format!(
                    "Memcached binary opcode 0x{:02x} is unsupported",
                    frame.opcode
                )]
            } else if sasl {
                vec![
                    "Memcached binary SASL is unsupported and credentials were omitted".to_string(),
                ]
            } else {
                Vec::new()
            };
            if sasl {
                request.key = None;
                request.value = None;
                request.extras = None;
            }
            c2s_pending
                .lock()
                .await
                .push_back(PendingMemcachedExchange {
                    targets: c2s_state.capture_memcached_dependency(
                        connection_id,
                        sequence,
                        c2s_context.target_port,
                        &request.command,
                        request.key.as_deref(),
                    ),
                    sequence,
                    request,
                    response_frames: Vec::new(),
                    response_frame_offsets_ms: Vec::new(),
                    replay_safe: !sasl && !unknown,
                    warnings,
                    started: Instant::now(),
                    request_started_at: chrono::Utc::now(),
                    termination: None,
                });
            upstream_write.write_all(&frame.raw).await?;
            bytes += frame.raw.len() as u64;
        }
        if c2s_termination
            .connection_end(TerminationSide::Client)
            .is_some()
        {
            let _ = c2s_upstream_control.reset();
        } else {
            let _ = upstream_write.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_context = context.clone();
    let s2c_pending = pending.clone();
    let s2c_capture_health = capture_health.clone();
    let s2c_client_write = client_write.clone();
    let s2c_termination = termination.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::new(
            ObservedIo::new(
                upstream_read,
                s2c_termination.clone(),
                TerminationSide::Server,
            ),
            max_frame_bytes,
        );
        let mut bytes = 0_u64;
        loop {
            let frame = match read_binary_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    s2c_termination.observe_server_eof();
                    break;
                }
                Err(error)
                    if reader.buffer.is_empty() && s2c_termination.observe_server_error(&error) =>
                {
                    break;
                }
                Err(error) => {
                    s2c_capture_health.activate(
                        &s2c_state,
                        format!(
                            "Memcached binary response parse failed; switched to raw forwarding: {error}"
                        ),
                    );
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(
                        &mut reader,
                        &mut *writer,
                        None,
                        &s2c_capture_health,
                        &s2c_state,
                        RawTrafficDirection::ServerToClient,
                    )
                    .await?;
                    break;
                }
            };
            if s2c_capture_health.is_degraded() {
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    &s2c_capture_health,
                    &s2c_state,
                    RawTrafficDirection::ServerToClient,
                )
                .await?;
                break;
            }
            if frame.magic != 0x81 {
                s2c_capture_health.activate(
                    &s2c_state,
                    "Memcached binary upstream sent request magic; switched to raw forwarding"
                        .to_string(),
                );
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(
                    &mut reader,
                    &mut *writer,
                    Some(&frame.raw),
                    &s2c_capture_health,
                    &s2c_state,
                    RawTrafficDirection::ServerToClient,
                )
                .await?;
                break;
            }
            let (quiet_completed, mut completed) =
                correlate_binary_response(&s2c_pending, &frame).await?;
            for exchange in quiet_completed {
                record_exchange(
                    &s2c_state,
                    connection_id,
                    &s2c_context,
                    MemcachedWireProtocol::Binary,
                    exchange,
                    true,
                    DependencyExchangeOutcome::NoResponse,
                    max_frame_bytes,
                )
                .await?;
            }
            if s2c_termination.snapshot().is_some_and(|observed| {
                observed.termination.side == TerminationSide::Client
                    && observed.termination.kind == crate::dependency::TerminationKind::Reset
            }) {
                if let Some(mut exchange) = completed {
                    exchange.response_frames.pop();
                    exchange.termination = s2c_termination.snapshot();
                    if !s2c_pending.lock().await.is_empty() {
                        exchange.replay_safe = false;
                        exchange.warnings.push("multiple in-flight Memcached requests share a termination; batch replay is unsupported".into());
                    }
                    record_exchange(
                        &s2c_state,
                        connection_id,
                        &s2c_context,
                        MemcachedWireProtocol::Binary,
                        exchange,
                        false,
                        DependencyExchangeOutcome::ClientTerminated,
                        max_frame_bytes,
                    )
                    .await?;
                } else if let Some(exchange) = s2c_pending
                    .lock()
                    .await
                    .iter_mut()
                    .find(|exchange| exchange.request.opaque == Some(frame.opaque))
                {
                    exchange.response_frames.pop();
                }
                break;
            }
            match s2c_client_write.lock().await.write_all(&frame.raw).await {
                Ok(()) => {
                    bytes += frame.raw.len() as u64;
                    if let Some(exchange) = completed.as_mut() {
                        exchange
                            .response_frame_offsets_ms
                            .push(exchange.started.elapsed().as_millis());
                    } else if let Some(exchange) = s2c_pending
                        .lock()
                        .await
                        .iter_mut()
                        .find(|exchange| exchange.request.opaque == Some(frame.opaque))
                    {
                        exchange
                            .response_frame_offsets_ms
                            .push(exchange.started.elapsed().as_millis());
                    }
                    if let Some(exchange) = completed {
                        record_exchange(
                            &s2c_state,
                            connection_id,
                            &s2c_context,
                            MemcachedWireProtocol::Binary,
                            exchange,
                            false,
                            DependencyExchangeOutcome::Response,
                            max_frame_bytes,
                        )
                        .await?;
                    }
                }
                Err(error) if s2c_termination.observe_client_io_error(&error) => {
                    s2c_capture_health.activate(
                        &s2c_state,
                        "Memcached response write failed after an unknown delivery prefix".into(),
                    );
                    if let Some(mut exchange) = completed {
                        exchange.termination = s2c_termination.snapshot();
                        exchange.replay_safe = false;
                        exchange
                            .warnings
                            .push("response write failed after an unknown delivery prefix".into());
                        exchange.response_frames.pop();
                        record_exchange(
                            &s2c_state,
                            connection_id,
                            &s2c_context,
                            MemcachedWireProtocol::Binary,
                            exchange,
                            false,
                            DependencyExchangeOutcome::ClientTerminated,
                            max_frame_bytes,
                        )
                        .await?;
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if s2c_termination
            .connection_end(TerminationSide::Server)
            .is_some()
        {
            let _ = client_control.reset();
        } else {
            let _ = s2c_client_write.lock().await.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let (c2s_result, s2c_result) = tokio::join!(c2s, s2c);
    let c2s_bytes = c2s_result.context("Memcached binary client task panicked")??;
    let s2c_bytes = s2c_result.context("Memcached binary server task panicked")??;
    let mut replay_safe = finish_pending(
        &state,
        connection_id,
        &context,
        MemcachedWireProtocol::Binary,
        &pending,
        &termination,
        max_frame_bytes,
    )
    .await?;
    if capture_health.is_degraded() {
        replay_safe = false;
    }
    Ok((c2s_bytes, s2c_bytes, replay_safe))
}

async fn correlate_binary_response(
    pending: &Arc<Mutex<VecDeque<PendingMemcachedExchange>>>,
    frame: &BinaryFrame,
) -> Result<(
    Vec<PendingMemcachedExchange>,
    Option<PendingMemcachedExchange>,
)> {
    let mut pending = pending.lock().await;
    let index = pending
        .iter()
        .position(|exchange| exchange.request.opaque == Some(frame.opaque))
        .ok_or_else(|| anyhow!("Memcached binary response opaque has no pending request"))?;
    let mut quiet_completed = Vec::new();
    for earlier in (0..index).rev() {
        if pending[earlier].request.quiet {
            quiet_completed.push(pending.remove(earlier).expect("quiet pending request"));
        }
    }
    quiet_completed.reverse();
    let index = pending
        .iter()
        .position(|exchange| exchange.request.opaque == Some(frame.opaque))
        .expect("response target still pending");
    pending[index].response_frames.push(frame.raw.to_vec());
    let request_opcode = pending[index].request.opcode.unwrap_or_default();
    let completed = if binary_response_is_complete(request_opcode, frame) {
        pending.remove(index)
    } else {
        None
    };
    Ok((quiet_completed, completed))
}

fn is_meta_command(command: &str) -> bool {
    matches!(command, "mg" | "ms" | "md" | "ma" | "me" | "mn")
}
