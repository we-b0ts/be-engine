use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppState;
use crate::DependencyExchangeOutcome;
use crate::dependency::TerminationSide;
use crate::dependency::termination::ConnectionTermination;
use crate::memcached::MemcachedWireProtocol;
use crate::recorder::{
    MemcachedConnectionEvent, MemcachedExchangeEvent, RecorderEvent, capture_body,
};

use super::{ConnectionContext, PendingMemcachedExchange};

pub(super) async fn finish_pending(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
    pending: &Arc<Mutex<VecDeque<PendingMemcachedExchange>>>,
    termination: &ConnectionTermination,
    max_frame_bytes: usize,
) -> Result<bool> {
    let exchanges = pending.lock().await.drain(..).collect::<Vec<_>>();
    let multiple_pending = exchanges
        .iter()
        .filter(|exchange| !exchange.request.quiet && !exchange.request.noreply)
        .count()
        > 1;
    let mut replay_safe = true;
    for mut exchange in exchanges {
        let no_response = exchange.request.quiet || exchange.request.noreply;
        let observed = termination
            .snapshot()
            .filter(|_| !termination.engine_stopped())
            .filter(|observed| observed.termination.side != TerminationSide::Engine)
            .filter(|observed| observed.at >= exchange.started);
        if !no_response && observed.is_none() {
            exchange.replay_safe = false;
            exchange.warnings.push(
                if termination.engine_stopped() {
                    "engine cleanup interrupted Memcached capture"
                } else if termination.peer_snapshot().is_some_and(|end| end.at < exchange.started) {
                    "Memcached request began after the recorded termination; post-terminal capture is unsupported"
                } else {
                    "connection closed before Memcached response"
                }
                .to_string(),
            );
            replay_safe = false;
        }
        if !no_response {
            exchange.termination = observed;
            if multiple_pending && observed.is_some() {
                exchange.replay_safe = false;
                exchange.warnings.push("multiple in-flight Memcached requests share a termination; batch replay is unsupported".into());
                replay_safe = false;
            }
        }
        record_exchange(
            state,
            connection_id,
            context,
            wire_protocol,
            exchange,
            no_response,
            if no_response {
                DependencyExchangeOutcome::NoResponse
            } else if let Some(observed) = observed {
                DependencyExchangeOutcome::Terminated(observed.termination)
            } else {
                DependencyExchangeOutcome::Response
            },
            max_frame_bytes,
        )
        .await?;
    }
    Ok(replay_safe)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_exchange(
    state: &AppState,
    connection_id: Uuid,
    context: &ConnectionContext,
    wire_protocol: MemcachedWireProtocol,
    mut pending: PendingMemcachedExchange,
    no_response: bool,
    mut outcome: DependencyExchangeOutcome,
    max_frame_bytes: usize,
) -> Result<()> {
    if pending
        .termination
        .is_some_and(|observed| observed.at < pending.started)
    {
        pending.termination = None;
        outcome = DependencyExchangeOutcome::Response;
        pending.replay_safe = false;
        pending.warnings.push("Memcached request began after the recorded termination; post-terminal capture is unsupported".into());
    }
    let outcome = pending.termination.map_or(outcome, |observed| {
        DependencyExchangeOutcome::Terminated(observed.termination)
    });
    let duration_ms = pending.termination.map_or_else(
        || pending.started.elapsed().as_millis(),
        |observed| observed.at.duration_since(pending.started).as_millis(),
    );
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
    let prefix_safe = outcome.termination().is_none()
        || pending.response_frame_offsets_ms.len() == response_frames.len()
            && pending
                .response_frame_offsets_ms
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
            && pending
                .response_frame_offsets_ms
                .iter()
                .all(|offset| *offset <= duration_ms);
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
    state.record_event_for_targets(
        RecorderEvent::MemcachedExchange(MemcachedExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence: pending.sequence,
            timestamp: Utc::now(),
            request_started_at: pending.request_started_at,
            client_addr: context.client_addr.clone(),
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
            response_frame_offsets_ms: pending.response_frame_offsets_ms,
            no_response,
            outcome,
            duration_ms,
            replay_safe: pending.replay_safe && captures_safe && prefix_safe,
            parse_warnings: pending.warnings,
        }),
        pending.targets,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_connection(
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

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.record_event(event);
    Ok(())
}
