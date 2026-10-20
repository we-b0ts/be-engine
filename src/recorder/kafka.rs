use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use chrono::Utc;
use kafka_protocol::messages::{ApiKey, RequestKind};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

use crate::AppState;
use crate::access_policy::AccessDecision;
use crate::dependency::DependencyExchangeOutcome;
use crate::dependency::TerminationSide;
use crate::dependency::termination::{ConnectionControl, ConnectionTermination, ObservedIo};
use crate::kafka::access::{classify_api, rejection_response};
use crate::kafka::{
    KafkaRecord, decode_request, decode_response, encode_response, read_frame, records_from_fetch,
    records_from_produce, replay_supports_api, response_correlation_id, write_frame,
};
use crate::recorder::{KafkaConnectionEvent, ProxyErrorEvent, RecorderEvent};

mod recording;
use recording::{
    FetchCompletion, ProduceCompletion, record_fetch_completion, record_produce_completion,
};

#[derive(Debug, Clone)]
pub(crate) struct KafkaConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
    pub(crate) upstream_addr: String,
}

#[derive(Debug)]
struct PendingRequest {
    api_key: ApiKey,
    api_version: i16,
    sequence: u64,
    started: Instant,
    kind: PendingKind,
}

#[derive(Debug)]
enum PendingKind {
    Produce {
        record_sequence: u64,
        records: Vec<KafkaRecord>,
    },
    Fetch(Vec<String>),
    Control,
    Unsupported(String),
}

pub(crate) async fn handle_connected(
    client: TcpStream,
    upstream: TcpStream,
    state: AppState,
    context: KafkaConnectionContext,
) -> Result<()> {
    let connection_id = Uuid::new_v4();
    let termination = ConnectionTermination::default();
    let _connection = state.dependency_connections().register_observed(
        "kafka",
        &[&client, &upstream],
        &termination,
    )?;
    let started = Instant::now();
    let pending = Arc::new(Mutex::new(HashMap::<i32, PendingRequest>::new()));
    let pending_changed = Arc::new(Notify::new());
    let replay_safe = Arc::new(AtomicBool::new(true));
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

    let max_frame_bytes = state
        .config()
        .recording
        .max_body_bytes
        .saturating_add(1024 * 1024);
    let client_control = ConnectionControl::new(&client)?;
    let upstream_control = ConnectionControl::new(&upstream)?;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, mut upstream_write) = upstream.into_split();
    let mut client_read =
        ObservedIo::new(client_read, termination.clone(), TerminationSide::Client);
    let mut upstream_read =
        ObservedIo::new(upstream_read, termination.clone(), TerminationSide::Server);
    let client_write = Arc::new(Mutex::new(client_write));

    let request_pending = pending.clone();
    let request_safe = replay_safe.clone();
    let request_state = state.clone();
    let request_context = context.clone();
    let request_client_write = client_write.clone();
    let request_pending_changed = pending_changed.clone();
    let request_termination = termination.clone();
    let requests = tokio::spawn(async move {
        let mut bytes = 0_u64;
        let mut request_sequence = 0_u64;
        let mut produce_sequence = 0_u64;
        'requests: loop {
            let before = client_read.bytes_read();
            let payload = match read_frame(&mut client_read, max_frame_bytes).await {
                Ok(Some(payload)) => payload,
                Ok(None) => {
                    request_termination.observe_client_eof();
                    break;
                }
                Err(error)
                    if client_read.bytes_read() == before
                        && request_termination.observe_client_error(&error) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            };
            bytes += payload.len() as u64 + 4;
            request_sequence += 1;
            let decoded = match decode_request(&payload) {
                Ok(decoded) => decoded,
                Err(error) => {
                    request_safe.store(false, Ordering::Release);
                    record_proxy_error(
                        &request_state,
                        &request_context,
                        format!("Kafka request parse failed: {error}"),
                    )
                    .await?;
                    if let Err(error) = write_frame(&mut upstream_write, &payload).await {
                        if request_termination.observe_server_error(&error) {
                            break;
                        }
                        return Err(error);
                    }
                    continue;
                }
            };

            let operation_class = classify_api(decoded.api_key);
            if request_state.access_decision(operation_class) == AccessDecision::Reject {
                request_state
                    .record_readonly_rejection(
                        "kafka",
                        operation_class,
                        format!("{:?}", decoded.api_key),
                        request_context.client_addr.clone(),
                        Some(request_context.target_addr.clone()),
                        "Kafka API is classified as a write operation",
                    )
                    .await;
                if let Some(response) = rejection_response(&decoded.request) {
                    let payload = encode_response(
                        decoded.header.correlation_id,
                        decoded.api_key,
                        decoded.header.request_api_version,
                        &response,
                    )?;
                    let mut client_write = request_client_write.lock().await;
                    if let Err(error) = write_frame(&mut *client_write, &payload).await {
                        if request_termination.observe_client_error(&error) {
                            break 'requests;
                        }
                        return Err(error);
                    }
                } else if !matches!(
                    &decoded.request,
                    RequestKind::Produce(request) if request.acks == 0
                ) {
                    loop {
                        let notified = request_pending_changed.notified();
                        if request_pending.lock().await.is_empty() {
                            break;
                        }
                        notified.await;
                    }
                    break 'requests;
                }
                continue;
            }

            let kind = if !replay_supports_api(decoded.api_key) {
                let reason = format!(
                    "Kafka API {:?} is outside the replay V1 profile",
                    decoded.api_key
                );
                request_safe.store(false, Ordering::Release);
                record_proxy_error(&request_state, &request_context, reason.clone()).await?;
                PendingKind::Unsupported(reason)
            } else {
                match decoded.api_key {
                    ApiKey::Produce => match records_from_produce(&decoded.request) {
                        Ok(records) => {
                            let record_sequence = produce_sequence + 1;
                            produce_sequence += records.len() as u64;
                            PendingKind::Produce {
                                record_sequence,
                                records,
                            }
                        }
                        Err(error) => {
                            request_safe.store(false, Ordering::Release);
                            record_proxy_error(
                                &request_state,
                                &request_context,
                                format!("unsupported Kafka Produce: {error}"),
                            )
                            .await?;
                            PendingKind::Unsupported(error.to_string())
                        }
                    },
                    ApiKey::Fetch => {
                        let RequestKind::Fetch(request) = &decoded.request else {
                            unreachable!();
                        };
                        let mut topics = request
                            .topics
                            .iter()
                            .map(|topic| topic.topic.to_string())
                            .collect::<Vec<_>>();
                        topics.sort();
                        topics.dedup();
                        PendingKind::Fetch(topics)
                    }
                    _ => PendingKind::Control,
                }
            };
            let request = PendingRequest {
                api_key: decoded.api_key,
                api_version: decoded.header.request_api_version,
                sequence: request_sequence,
                started: Instant::now(),
                kind,
            };
            let no_response = matches!(
                &decoded.request,
                RequestKind::Produce(request) if request.acks == 0
            );
            let correlation_id = decoded.header.correlation_id;
            if no_response {
                if let Err(error) = write_frame(&mut upstream_write, &payload).await {
                    if request_termination.observe_server_error(&error) {
                        break;
                    }
                    return Err(error);
                }
                record_client_request_without_response(
                    &request_state,
                    connection_id,
                    &request_context,
                    request,
                )
                .await?;
                continue;
            }
            if request_pending
                .lock()
                .await
                .insert(correlation_id, request)
                .is_some()
            {
                request_safe.store(false, Ordering::Release);
                record_proxy_error(
                    &request_state,
                    &request_context,
                    format!("duplicate in-flight Kafka correlation id {correlation_id}"),
                )
                .await?;
            }
            if let Err(error) = write_frame(&mut upstream_write, &payload).await {
                if request_termination.observe_server_error(&error) {
                    break;
                }
                return Err(error);
            }
        }
        if request_termination
            .connection_end(TerminationSide::Client)
            .is_some()
        {
            let _ = upstream_control.reset();
        } else {
            let _ = upstream_write.shutdown().await;
        }
        Ok::<u64, anyhow::Error>(bytes)
    });

    let response_pending = pending.clone();
    let response_safe = replay_safe.clone();
    let response_state = state.clone();
    let response_context = context.clone();
    let response_client_write = client_write.clone();
    let response_pending_changed = pending_changed.clone();
    let response_termination = termination.clone();
    let responses = tokio::spawn(async move {
        let result = async {
        let mut bytes = 0_u64;
        let mut delivery_sequence = 0_u64;
        loop {
            upstream_read.begin_capture(max_frame_bytes.saturating_add(4));
            let before = upstream_read.bytes_read();
            let read = read_frame(&mut upstream_read, max_frame_bytes).await;
            let payload = match read {
                Ok(Some(payload)) => payload,
                Ok(None) => {
                    response_termination.observe_server_eof();
                    break;
                }
                Err(error)
                    if upstream_read.bytes_read() == before
                        && response_termination.observe_server_error(&error) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            };
            bytes += payload.len() as u64 + 4;
            let correlation_id = response_correlation_id(&payload)?;
            let request = response_pending.lock().await.remove(&correlation_id);
            response_pending_changed.notify_waiters();
            let Some(request) = request else {
                response_safe.store(false, Ordering::Release);
                record_proxy_error(
                    &response_state,
                    &response_context,
                    format!(
                        "Kafka response correlation id {correlation_id} has no pending request"
                    ),
                )
                .await?;
                upstream_read.begin_capture(0);
                write_frame(&mut *response_client_write.lock().await, &payload).await?;
                continue;
            };
            if response_termination.snapshot().is_some_and(|observed| {
                observed.termination.side == TerminationSide::Client
                    && observed.termination.kind == crate::dependency::TerminationKind::Reset
            }) {
                if !response_pending.lock().await.is_empty() {
                    response_safe.store(false, Ordering::Release);
                    record_proxy_error(&response_state, &response_context, "multiple in-flight Kafka requests share a termination; batch replay is unsupported".into()).await?;
                }
                record_terminated_request(
                    &response_state,
                    connection_id,
                    &mut delivery_sequence,
                    &response_context,
                    request,
                    &response_termination,
                )
                .await?;
                break;
            }
            upstream_read.begin_capture(0);
            let write_result = {
                let mut client_write = response_client_write.lock().await;
                write_frame(&mut *client_write, &payload).await
            };
            match write_result {
                Ok(()) => {
                    if let Err(error) = record_completed_response(
                        &response_state,
                        connection_id,
                        &mut delivery_sequence,
                        &response_context,
                        request,
                        &payload,
                    )
                    .await
                    {
                        response_safe.store(false, Ordering::Release);
                        record_proxy_error(&response_state, &response_context, error.to_string())
                            .await?;
                    }
                }
                Err(error) if response_termination.observe_client_error(&error) => {
                    response_safe.store(false, Ordering::Release);
                    record_proxy_error(
                        &response_state,
                        &response_context,
                        "Kafka response write failed after an unknown delivery prefix".into(),
                    )
                    .await?;
                    record_terminated_request(
                        &response_state,
                        connection_id,
                        &mut delivery_sequence,
                        &response_context,
                        request,
                        &response_termination,
                    )
                    .await?;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok::<u64, anyhow::Error>(bytes)
        }.await;
        if result.is_err() && !response_termination.engine_stopped() {
            response_safe.store(false, Ordering::Release);
            let mut writer = response_client_write.lock().await;
            let _ = crate::dependency::termination::forward_captured(
                &mut upstream_read,
                &mut *writer,
                &response_termination,
                TerminationSide::Server,
            )
            .await;
        }
        if let Some(observed) = response_termination
            .connection_end(TerminationSide::Server)
            .or_else(|| response_termination.observed(TerminationSide::Server))
        {
            match observed.termination.kind {
                crate::dependency::TerminationKind::Reset => {
                    let _ = client_control.reset();
                }
                crate::dependency::TerminationKind::Eof => {
                    let _ = response_client_write.lock().await.shutdown().await;
                }
                crate::dependency::TerminationKind::Cancelled => {}
            }
        }
        result
    });

    let (requests, responses) = tokio::join!(requests, responses);
    let transfer = async {
        Ok::<_, anyhow::Error>((
            requests.context("Kafka request task panicked")??,
            responses.context("Kafka response task panicked")??,
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
    if incomplete.len() > 1 && termination.outcome_since(started).is_some() {
        replay_safe.store(false, Ordering::Release);
        record_proxy_error(
            &state,
            &context,
            "multiple in-flight Kafka requests share a termination; batch replay is unsupported"
                .into(),
        )
        .await?;
    }
    if !incomplete.is_empty() {
        if error.is_none() && termination.outcome_since(started).is_some() {
            let mut delivery_sequence = 0;
            for request in incomplete {
                if termination.outcome_since(request.started).is_none() {
                    replay_safe.store(false, Ordering::Release);
                    record_proxy_error(&state, &context, "Kafka request began after the recorded termination; post-terminal capture is unsupported".into()).await?;
                    continue;
                }
                record_terminated_request(
                    &state,
                    connection_id,
                    &mut delivery_sequence,
                    &context,
                    request,
                    &termination,
                )
                .await?;
            }
        } else {
            replay_safe.store(false, Ordering::Release);
            record_proxy_error(
                &state,
                &context,
                if termination.engine_stopped() {
                    "engine cleanup interrupted Kafka capture"
                } else {
                    "Kafka connection closed with incomplete requests"
                }
                .to_string(),
            )
            .await?;
        }
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

async fn record_client_request_without_response(
    state: &AppState,
    connection_id: Uuid,
    context: &KafkaConnectionContext,
    request: PendingRequest,
) -> Result<()> {
    let PendingKind::Produce {
        record_sequence,
        records,
    } = request.kind
    else {
        return Err(anyhow!("Kafka no-response request was not Produce"));
    };
    record_produce_completion(
        state,
        connection_id,
        context,
        ProduceCompletion {
            request_sequence: request.sequence,
            record_sequence,
            api_version: request.api_version,
            started: request.started,
            records,
            response: None,
            outcome: DependencyExchangeOutcome::NoResponse,
            duration_ms: None,
        },
    )
    .await
}

async fn record_completed_response(
    state: &AppState,
    connection_id: Uuid,
    delivery_sequence: &mut u64,
    context: &KafkaConnectionContext,
    request: PendingRequest,
    payload: &Bytes,
) -> Result<()> {
    match request.kind {
        PendingKind::Produce {
            record_sequence,
            records,
        } => {
            let response = decode_response(payload, request.api_key, request.api_version)?.response;
            record_produce_completion(
                state,
                connection_id,
                context,
                ProduceCompletion {
                    request_sequence: request.sequence,
                    record_sequence,
                    api_version: request.api_version,
                    started: request.started,
                    records,
                    response: Some(response),
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: None,
                },
            )
            .await
        }
        PendingKind::Fetch(topics) => {
            let response = decode_response(payload, request.api_key, request.api_version)?.response;
            let records = records_from_fetch(&response)?;
            record_fetch_completion(
                state,
                connection_id,
                delivery_sequence,
                context,
                FetchCompletion {
                    sequence: request.sequence,
                    api_version: request.api_version,
                    started: request.started,
                    topics,
                    records,
                    outcome: DependencyExchangeOutcome::Response,
                    duration_ms: None,
                },
            )
            .await
        }
        PendingKind::Control | PendingKind::Unsupported(_) => Ok(()),
    }
}

async fn record_terminated_request(
    state: &AppState,
    connection_id: Uuid,
    delivery_sequence: &mut u64,
    context: &KafkaConnectionContext,
    request: PendingRequest,
    termination: &ConnectionTermination,
) -> Result<()> {
    let (outcome, duration_ms) = termination
        .outcome_since(request.started)
        .ok_or_else(|| anyhow!("Kafka capture ended without peer termination evidence"))?;
    match request.kind {
        PendingKind::Produce {
            record_sequence,
            records,
        } => {
            record_produce_completion(
                state,
                connection_id,
                context,
                ProduceCompletion {
                    request_sequence: request.sequence,
                    record_sequence,
                    api_version: request.api_version,
                    started: request.started,
                    records,
                    response: None,
                    outcome,
                    duration_ms: Some(duration_ms),
                },
            )
            .await
        }
        PendingKind::Fetch(topics) => {
            record_fetch_completion(
                state,
                connection_id,
                delivery_sequence,
                context,
                FetchCompletion {
                    sequence: request.sequence,
                    api_version: request.api_version,
                    started: request.started,
                    topics,
                    records: Vec::new(),
                    outcome,
                    duration_ms: Some(duration_ms),
                },
            )
            .await
        }
        PendingKind::Control => Ok(()),
        PendingKind::Unsupported(reason) => {
            let _ = reason;
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_connection(
    state: &AppState,
    id: Uuid,
    context: &KafkaConnectionContext,
    phase: &str,
    duration_ms: Option<u128>,
    client_to_server_bytes: u64,
    server_to_client_bytes: u64,
    replay_safe: bool,
    error: Option<String>,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::KafkaConnection(KafkaConnectionEvent {
            id,
            timestamp: Utc::now(),
            phase: phase.to_string(),
            client_addr: context.client_addr.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
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
    context: &KafkaConnectionContext,
    error: String,
) -> Result<()> {
    record_event(
        state,
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: None,
            timestamp: Utc::now(),
            protocol: "kafka".to_string(),
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
