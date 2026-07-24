use std::collections::HashMap;
use std::net::Ipv4Addr;
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
use crate::dependency::DependencyExchangeOutcome;
use crate::dependency::termination::ConnectionTermination;
use crate::motan::{Frame, RequestIdentity, read_frame, response_status};
use crate::recorder::{
    MotanConnectionEvent, MotanExchangeEvent, ProxyErrorEvent, RecorderEvent, capture_body,
};

#[derive(Debug, Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) advertised_ip: Ipv4Addr,
    pub(crate) upstream_addr: String,
}

#[derive(Debug)]
struct PendingRequest {
    sequence: u64,
    frame: Frame,
    identity: RequestIdentity,
    started: Instant,
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: ConnectionContext,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let started = Instant::now();
    let pending = Arc::new(Mutex::new(HashMap::<u64, PendingRequest>::new()));
    let requests_ended = Arc::new(Notify::new());
    let responses_ended = Arc::new(Notify::new());
    let replay_safe = Arc::new(AtomicBool::new(true));
    let termination = ConnectionTermination::default();
    record_connection(
        &state,
        connection_id,
        &context,
        "opened",
        None,
        0,
        0,
        true,
        None,
    )
    .await?;

    let max_frame_bytes = state.config().recording.max_body_bytes.saturating_add(32);
    let (mut client_read, client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let client_write = Arc::new(Mutex::new(client_write));

    let request_pending = pending.clone();
    let request_ended = requests_ended.clone();
    let response_ended_for_requests = responses_ended.clone();
    let request_safe = replay_safe.clone();
    let request_termination = termination.clone();
    let requests = tokio::spawn(async move {
        let result = async {
            let mut bytes = 0_u64;
            let mut sequence = 0_u64;
            loop {
                let frame = tokio::select! {
                    _ = response_ended_for_requests.notified() => None,
                    frame = read_frame(&mut client_read, max_frame_bytes) => Some(frame),
                };
                let Some(frame) = frame else {
                    break;
                };
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        request_termination.observe_client_eof();
                        break;
                    }
                    Err(error) if request_termination.observe_client_error(&error) => break,
                    Err(error) => return Err(error),
                };
                if !frame.request {
                    return Err(anyhow!("Motan client sent a response frame"));
                }
                let identity = frame
                    .request_identity()
                    .context("failed to decode Motan request identity")?;
                sequence += 1;
                bytes = bytes.saturating_add(frame.raw.len() as u64);
                let request_id = frame.request_id;
                let request = PendingRequest {
                    sequence,
                    frame,
                    identity,
                    started: Instant::now(),
                };
                let raw = request.frame.raw.clone();
                if request_pending
                    .lock()
                    .await
                    .insert(request_id, request)
                    .is_some()
                {
                    request_safe.store(false, Ordering::Release);
                    return Err(anyhow!("duplicate in-flight Motan request id {request_id}"));
                }
                if let Err(error) = upstream_write.write_all(&raw).await {
                    let error = anyhow!(error).context("failed to forward Motan request");
                    if request_termination.observe_server_error(&error) {
                        break;
                    }
                    return Err(error);
                }
            }
            let _ = upstream_write.shutdown().await;
            Ok::<u64, anyhow::Error>(bytes)
        }
        .await;
        request_ended.notify_one();
        result
    });

    let response_pending = pending.clone();
    let response_ended = responses_ended.clone();
    let request_ended_for_responses = requests_ended.clone();
    let response_safe = replay_safe.clone();
    let response_state = state.clone();
    let response_context = context.clone();
    let response_client_write = client_write.clone();
    let response_termination = termination.clone();
    let responses = tokio::spawn(async move {
        let result = async {
            let mut bytes = 0_u64;
            loop {
                let frame = tokio::select! {
                    _ = request_ended_for_responses.notified() => None,
                    frame = read_frame(&mut upstream_read, max_frame_bytes) => Some(frame),
                };
                let Some(frame) = frame else {
                    break;
                };
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        response_termination.observe_server_eof();
                        break;
                    }
                    Err(error) if response_termination.observe_server_error(&error) => break,
                    Err(error) => return Err(error),
                };
                if frame.request {
                    return Err(anyhow!("Motan server sent a request frame"));
                }
                bytes = bytes.saturating_add(frame.raw.len() as u64);
                let request = response_pending.lock().await.remove(&frame.request_id);
                let Some(request) = request else {
                    response_safe.store(false, Ordering::Release);
                    record_proxy_error(
                        &response_state,
                        &response_context,
                        format!(
                            "Motan response request id {} has no pending request",
                            frame.request_id
                        ),
                    )
                    .await?;
                    response_client_write
                        .lock()
                        .await
                        .write_all(&frame.raw)
                        .await?;
                    continue;
                };
                let outcome = if response_termination.client_ended_first() {
                    DependencyExchangeOutcome::ClientTerminated
                } else {
                    match response_client_write
                        .lock()
                        .await
                        .write_all(&frame.raw)
                        .await
                    {
                        Ok(()) => DependencyExchangeOutcome::Response,
                        Err(error) if response_termination.observe_client_io_error(&error) => {
                            DependencyExchangeOutcome::ClientTerminated
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                record_exchange(
                    &response_state,
                    connection_id,
                    &response_context,
                    request,
                    Some(&frame),
                    outcome,
                    max_frame_bytes,
                )
                .await?;
                if outcome.is_client_terminated() {
                    break;
                }
            }
            let _ = response_client_write.lock().await.shutdown().await;
            Ok::<u64, anyhow::Error>(bytes)
        }
        .await;
        response_ended.notify_one();
        result
    });

    let (requests, responses) = tokio::join!(requests, responses);
    let transfer = async {
        Ok::<_, anyhow::Error>((
            requests.context("Motan request task panicked")??,
            responses.context("Motan response task panicked")??,
        ))
    }
    .await;
    let (client_to_server_bytes, server_to_client_bytes, error) = match transfer {
        Ok((client_bytes, server_bytes)) => (client_bytes, server_bytes, None),
        Err(error) => {
            replay_safe.store(false, Ordering::Release);
            record_proxy_error(&state, &context, error.to_string()).await?;
            (0, 0, Some(error.to_string()))
        }
    };

    let incomplete = pending
        .lock()
        .await
        .drain()
        .map(|(_, request)| request)
        .collect::<Vec<_>>();
    if termination.client_ended_first() {
        for request in incomplete {
            record_exchange(
                &state,
                connection_id,
                &context,
                request,
                None,
                DependencyExchangeOutcome::ClientTerminated,
                max_frame_bytes,
            )
            .await?;
        }
    } else if !incomplete.is_empty() {
        replay_safe.store(false, Ordering::Release);
        record_proxy_error(
            &state,
            &context,
            "Motan connection closed with incomplete requests".to_string(),
        )
        .await?;
    }

    let safe = replay_safe.load(Ordering::Acquire);
    record_connection(
        &state,
        connection_id,
        &context,
        "closed",
        Some(started.elapsed().as_millis()),
        client_to_server_bytes,
        server_to_client_bytes,
        safe,
        error.clone(),
    )
    .await?;
    if let Some(error) = error {
        return Err(anyhow!(error));
    }
    Ok(())
}

async fn record_exchange(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    request: PendingRequest,
    response: Option<&Frame>,
    outcome: DependencyExchangeOutcome,
    max_frame_bytes: usize,
) -> Result<()> {
    let request_capture = capture_body(&request.frame.raw, max_frame_bytes);
    let response_capture = capture_body(
        response.map_or(&[][..], |frame| frame.raw.as_ref()),
        max_frame_bytes,
    );
    let heartbeat = request.identity.is_heartbeat();
    let command = request.identity.command();
    let replay_safe = !request_capture.truncated
        && !response_capture.truncated
        && (outcome.is_client_terminated() || response.is_some());
    record_event(
        state,
        RecorderEvent::MotanExchange(MotanExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence: request.sequence,
            timestamp: Utc::now(),
            client_addr: context.client_addr.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            advertised_ip: context.advertised_ip,
            upstream_addr: context.upstream_addr.clone(),
            codec_version: request.frame.codec_version,
            interface_name: request.identity.interface_name,
            method_name: request.identity.method_name,
            parameter_desc: request.identity.parameter_desc,
            method_sign: request.identity.method_sign,
            command,
            request: request_capture,
            response_status: response
                .map_or("client_terminated", response_status)
                .to_string(),
            response: response_capture,
            heartbeat,
            outcome,
            duration_ms: request.started.elapsed().as_millis(),
            replay_safe,
            parse_warnings: Vec::new(),
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn record_connection(
    state: &AppState,
    id: Uuid,
    context: &ConnectionContext,
    phase: &str,
    duration_ms: Option<u128>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    replay_safe: bool,
    error: Option<String>,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::MotanConnection(MotanConnectionEvent {
            id,
            timestamp: Utc::now(),
            phase: phase.to_string(),
            client_addr: context.client_addr.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            advertised_ip: context.advertised_ip,
            upstream_addr: context.upstream_addr.clone(),
            duration_ms,
            client_to_server_bytes,
            server_to_client_bytes,
            replay_safe,
            error,
        }),
    )
    .await
}

async fn record_proxy_error(
    state: &AppState,
    context: &ConnectionContext,
    error: String,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "motan".to_string(),
            client_addr: context.client_addr.clone(),
            target: Some(context.target_addr.clone()),
            error,
        }),
    )
    .await
}

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.record_event(event);
    Ok(())
}

#[cfg(test)]
mod tests;
