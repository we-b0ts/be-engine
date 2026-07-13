use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::AccessDecision;
use crate::memcached::access::classify_request;
use crate::memcached::{
    BinaryFrame, BufferedReader, MemcachedRequest, MemcachedWireProtocol,
    binary_access_denied_response, binary_response_is_complete, read_binary_frame,
    read_text_request, read_text_response,
};
use crate::recorder::{
    MemcachedConnectionEvent, MemcachedExchangeEvent, RecorderEvent, capture_body,
};

mod fallback;
#[cfg(test)]
mod tests;

use fallback::{activate_raw_fallback, forward_buffer_and_copy};

#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) client_process: Option<crate::recorder::ProcessInfo>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) upstream_addr: String,
}

#[derive(Debug)]
struct PendingMemcachedExchange {
    sequence: u64,
    request: MemcachedRequest,
    response_frames: Vec<Vec<u8>>,
    replay_safe: bool,
    warnings: Vec<String>,
    started: Instant,
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
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
) -> Result<(u64, u64, bool)> {
    let max_frame_bytes = state.config().recording.max_body_bytes;
    let pending = Arc::new(Mutex::new(VecDeque::<PendingMemcachedExchange>::new()));
    let raw_fallback = Arc::new(AtomicBool::new(false));
    let fallback_reason = Arc::new(Mutex::new(None::<String>));
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let pending_drained = Arc::new(Notify::new());
    let c2s_state = state.clone();
    let c2s_context = context.clone();
    let c2s_pending = pending.clone();
    let c2s_raw_fallback = raw_fallback.clone();
    let c2s_fallback_reason = fallback_reason.clone();
    let c2s_client_write = client_write.clone();
    let c2s_pending_drained = pending_drained.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::new(client_read, max_frame_bytes);
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            let request = match read_text_request(&mut reader).await {
                Ok(Some(request)) => request,
                Ok(None) => break,
                Err(error) => {
                    activate_raw_fallback(
                        &c2s_raw_fallback,
                        &c2s_fallback_reason,
                        format!(
                            "Memcached text request parse failed; switched to raw forwarding: {error}"
                        ),
                        &c2s_state,
                        &c2s_context,
                    )
                    .await?;
                    bytes += forward_buffer_and_copy(&mut reader, &mut upstream_write).await?;
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
                        c2s_context.client_process.clone(),
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
            upstream_write.write_all(&request.raw).await?;
            bytes += request.raw.len() as u64;
            let pending_exchange = PendingMemcachedExchange {
                sequence,
                request,
                response_frames: Vec::new(),
                replay_safe,
                warnings,
                started: Instant::now(),
            };
            if no_response {
                record_exchange(
                    &c2s_state,
                    connection_id,
                    &c2s_context,
                    MemcachedWireProtocol::Text,
                    pending_exchange,
                    true,
                    max_frame_bytes,
                )
                .await?;
            } else {
                c2s_pending.lock().await.push_back(pending_exchange);
            }
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_context = context.clone();
    let s2c_pending = pending.clone();
    let s2c_raw_fallback = raw_fallback.clone();
    let s2c_fallback_reason = fallback_reason.clone();
    let s2c_client_write = client_write.clone();
    let s2c_pending_drained = pending_drained.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::new(upstream_read, max_frame_bytes);
        let mut bytes = 0_u64;
        loop {
            let command = {
                let pending = s2c_pending.lock().await;
                pending
                    .front()
                    .map(|exchange| exchange.request.command.clone())
            };
            let Some(command) = command else {
                if reader.inner.readable().await.is_err() {
                    break;
                }
                if !s2c_pending.lock().await.is_empty() {
                    continue;
                }
                if s2c_raw_fallback.load(Ordering::Acquire) {
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                    break;
                }
                let mut probe = [0_u8; 1];
                match reader.inner.peek(&mut probe).await {
                    Ok(0) => break,
                    Ok(_) => {
                        activate_raw_fallback(
                            &s2c_raw_fallback,
                            &s2c_fallback_reason,
                            "Memcached text response has no pending request; switched to raw forwarding"
                                .to_string(),
                            &s2c_state,
                            &s2c_context,
                        )
                        .await?;
                        let mut writer = s2c_client_write.lock().await;
                        bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                        break;
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            let response = match read_text_response(&mut reader, &command).await {
                Ok(Some(response)) => response,
                Ok(None) => break,
                Err(error) => {
                    activate_raw_fallback(
                        &s2c_raw_fallback,
                        &s2c_fallback_reason,
                        format!(
                            "Memcached text response parse failed; switched to raw forwarding: {error}"
                        ),
                        &s2c_state,
                        &s2c_context,
                    )
                    .await?;
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                    break;
                }
            };
            if s2c_raw_fallback.load(Ordering::Acquire) {
                s2c_client_write.lock().await.write_all(&response).await?;
                bytes += response.len() as u64;
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                break;
            }
            let mut exchange = s2c_pending
                .lock()
                .await
                .pop_front()
                .expect("pending Memcached text request");
            s2c_pending_drained.notify_waiters();
            exchange.response_frames.push(response.to_vec());
            record_exchange(
                &s2c_state,
                connection_id,
                &s2c_context,
                MemcachedWireProtocol::Text,
                exchange,
                false,
                max_frame_bytes,
            )
            .await?;
            s2c_client_write.lock().await.write_all(&response).await?;
            bytes += response.len() as u64;
        }
        let _ = s2c_client_write.lock().await.shutdown().await;
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
        max_frame_bytes,
    )
    .await?;
    if fallback_reason.lock().await.is_some() {
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
) -> Result<(u64, u64, bool)> {
    let max_frame_bytes = state.config().recording.max_body_bytes;
    let pending = Arc::new(Mutex::new(VecDeque::<PendingMemcachedExchange>::new()));
    let raw_fallback = Arc::new(AtomicBool::new(false));
    let fallback_reason = Arc::new(Mutex::new(None::<String>));
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));
    let c2s_pending = pending.clone();
    let c2s_raw_fallback = raw_fallback.clone();
    let c2s_fallback_reason = fallback_reason.clone();
    let c2s_state = state.clone();
    let c2s_context = context.clone();
    let c2s_client_write = client_write.clone();
    let c2s = tokio::spawn(async move {
        let mut reader = BufferedReader::new(client_read, max_frame_bytes);
        let mut sequence = 0_u64;
        let mut bytes = 0_u64;
        loop {
            let frame = match read_binary_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    activate_raw_fallback(
                        &c2s_raw_fallback,
                        &c2s_fallback_reason,
                        format!(
                            "Memcached binary request parse failed; switched to raw forwarding: {error}"
                        ),
                        &c2s_state,
                        &c2s_context,
                    )
                    .await?;
                    bytes += forward_buffer_and_copy(&mut reader, &mut upstream_write).await?;
                    break;
                }
            };
            let mut request = match frame.as_request() {
                Ok(request) => request,
                Err(error) => {
                    activate_raw_fallback(
                        &c2s_raw_fallback,
                        &c2s_fallback_reason,
                        format!(
                            "Memcached binary request validation failed; switched to raw forwarding: {error}"
                        ),
                        &c2s_state,
                        &c2s_context,
                    )
                    .await?;
                    upstream_write.write_all(&frame.raw).await?;
                    bytes += frame.raw.len() as u64;
                    bytes += forward_buffer_and_copy(&mut reader, &mut upstream_write).await?;
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
                        c2s_context.client_process.clone(),
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
                    sequence,
                    request,
                    response_frames: Vec::new(),
                    replay_safe: !sasl && !unknown,
                    warnings,
                    started: Instant::now(),
                });
            upstream_write.write_all(&frame.raw).await?;
            bytes += frame.raw.len() as u64;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let s2c_state = state.clone();
    let s2c_context = context.clone();
    let s2c_pending = pending.clone();
    let s2c_raw_fallback = raw_fallback.clone();
    let s2c_fallback_reason = fallback_reason.clone();
    let s2c_client_write = client_write.clone();
    let s2c = tokio::spawn(async move {
        let mut reader = BufferedReader::new(upstream_read, max_frame_bytes);
        let mut bytes = 0_u64;
        loop {
            let frame = match read_binary_frame(&mut reader).await {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    activate_raw_fallback(
                        &s2c_raw_fallback,
                        &s2c_fallback_reason,
                        format!(
                            "Memcached binary response parse failed; switched to raw forwarding: {error}"
                        ),
                        &s2c_state,
                        &s2c_context,
                    )
                    .await?;
                    let mut writer = s2c_client_write.lock().await;
                    bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                    break;
                }
            };
            if s2c_raw_fallback.load(Ordering::Acquire) {
                s2c_client_write.lock().await.write_all(&frame.raw).await?;
                bytes += frame.raw.len() as u64;
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                break;
            }
            if frame.magic != 0x81 {
                activate_raw_fallback(
                    &s2c_raw_fallback,
                    &s2c_fallback_reason,
                    "Memcached binary upstream sent request magic; switched to raw forwarding"
                        .to_string(),
                    &s2c_state,
                    &s2c_context,
                )
                .await?;
                s2c_client_write.lock().await.write_all(&frame.raw).await?;
                bytes += frame.raw.len() as u64;
                let mut writer = s2c_client_write.lock().await;
                bytes += forward_buffer_and_copy(&mut reader, &mut *writer).await?;
                break;
            }
            let (quiet_completed, completed) =
                correlate_binary_response(&s2c_pending, &frame).await?;
            for exchange in quiet_completed {
                record_exchange(
                    &s2c_state,
                    connection_id,
                    &s2c_context,
                    MemcachedWireProtocol::Binary,
                    exchange,
                    true,
                    max_frame_bytes,
                )
                .await?;
            }
            if let Some(exchange) = completed {
                record_exchange(
                    &s2c_state,
                    connection_id,
                    &s2c_context,
                    MemcachedWireProtocol::Binary,
                    exchange,
                    false,
                    max_frame_bytes,
                )
                .await?;
            }
            s2c_client_write.lock().await.write_all(&frame.raw).await?;
            bytes += frame.raw.len() as u64;
        }
        let _ = s2c_client_write.lock().await.shutdown().await;
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
        max_frame_bytes,
    )
    .await?;
    if fallback_reason.lock().await.is_some() {
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

async fn finish_pending(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
    pending: &Arc<Mutex<VecDeque<PendingMemcachedExchange>>>,
    max_frame_bytes: usize,
) -> Result<bool> {
    let exchanges = pending.lock().await.drain(..).collect::<Vec<_>>();
    let mut replay_safe = true;
    for mut exchange in exchanges {
        let no_response = exchange.request.quiet || exchange.request.noreply;
        if !no_response {
            exchange.replay_safe = false;
            exchange
                .warnings
                .push("connection closed before Memcached response".to_string());
            replay_safe = false;
        }
        record_exchange(
            state,
            connection_id,
            context,
            wire_protocol,
            exchange,
            no_response,
            max_frame_bytes,
        )
        .await?;
    }
    Ok(replay_safe)
}

async fn record_exchange(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
    pending: PendingMemcachedExchange,
    no_response: bool,
    max_frame_bytes: usize,
) -> Result<()> {
    let request = pending.request;
    let key = request
        .key
        .as_ref()
        .map(|value| capture_body(value, max_frame_bytes));
    let args = request
        .args
        .iter()
        .map(|value| capture_body(value, max_frame_bytes))
        .collect::<Vec<_>>();
    let value = request
        .value
        .as_ref()
        .map(|value| capture_body(value, max_frame_bytes));
    let extras = request
        .extras
        .as_ref()
        .map(|value| capture_body(value, max_frame_bytes));
    let response_frames = pending
        .response_frames
        .iter()
        .map(|frame| capture_body(frame, max_frame_bytes))
        .collect::<Vec<_>>();
    let captures_safe = key.as_ref().is_none_or(|capture| !capture.truncated)
        && value.as_ref().is_none_or(|capture| !capture.truncated)
        && extras.as_ref().is_none_or(|capture| !capture.truncated)
        && args.iter().all(|capture| !capture.truncated)
        && response_frames.iter().all(|capture| !capture.truncated);
    let response_status = if no_response {
        "no_response".to_string()
    } else if wire_protocol == MemcachedWireProtocol::Binary {
        pending
            .response_frames
            .last()
            .filter(|frame| frame.len() >= 8)
            .map(|frame| u16::from_be_bytes([frame[6], frame[7]]).to_string())
            .unwrap_or_else(|| "incomplete".to_string())
    } else {
        pending
            .response_frames
            .first()
            .and_then(|frame| frame.split(|byte| *byte == b'\r').next())
            .map(|line| String::from_utf8_lossy(line).to_string())
            .unwrap_or_else(|| "incomplete".to_string())
    };
    record_event(
        state,
        RecorderEvent::MemcachedExchange(MemcachedExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence: pending.sequence,
            timestamp: Utc::now(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            upstream_addr: context.upstream_addr.clone(),
            wire_protocol: wire_protocol.as_str().to_string(),
            command: request.command,
            opcode: request.opcode,
            opaque: request.opaque,
            key,
            args,
            value,
            extras,
            cas: request.cas,
            noreply: request.noreply,
            quiet: request.quiet,
            response_status,
            response_frames,
            no_response,
            duration_ms: pending.started.elapsed().as_millis(),
            replay_safe: pending.replay_safe && captures_safe,
            parse_warnings: pending.warnings,
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn record_connection(
    state: &AppState,
    id: Uuid,
    context: &ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
    phase: &str,
    duration_ms: Option<u128>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    replay_safe: bool,
    error: Option<String>,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::MemcachedConnection(MemcachedConnectionEvent {
            id,
            timestamp: Utc::now(),
            phase: phase.to_string(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            upstream_addr: context.upstream_addr.clone(),
            wire_protocol: wire_protocol.as_str().to_string(),
            duration_ms,
            client_to_server_bytes,
            server_to_client_bytes,
            replay_safe,
            error,
        }),
    )
    .await
}

fn is_meta_command(command: &str) -> bool {
    matches!(command, "mg" | "ms" | "md" | "ma" | "me" | "mn")
}

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.recorder().record(event.clone()).await?;
    state.record_dependency_if_relevant(&event).await;
    Ok(())
}
