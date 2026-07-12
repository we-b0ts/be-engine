use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use kafka_protocol::messages::{ApiKey, ResponseKind};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::AppState;
use crate::recorder::{
    KafkaConnectionEvent, KafkaDeliveryEvent, KafkaHeaderCapture, KafkaProduceEvent, ProcessInfo,
    ProxyErrorEvent, RecorderEvent, capture_body,
};

use crate::kafka::{
    KafkaRecord, decode_request, decode_response, read_frame, records_from_fetch,
    records_from_produce, replay_supports_api, response_correlation_id, write_frame,
};

#[derive(Debug, Clone)]
pub(crate) struct KafkaConnectionContext {
    pub(crate) client_addr: Option<String>,
    pub(crate) client_process: Option<ProcessInfo>,
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

struct ProduceCompletion {
    sequence: u64,
    api_version: i16,
    started: Instant,
    records: Vec<KafkaRecord>,
    response: ResponseKind,
}

#[derive(Debug)]
enum PendingKind {
    Produce(Vec<KafkaRecord>),
    Fetch,
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
    let started = Instant::now();
    let pending = Arc::new(Mutex::new(HashMap::<i32, PendingRequest>::new()));
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
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let request_pending = pending.clone();
    let request_safe = replay_safe.clone();
    let request_state = state.clone();
    let request_context = context.clone();
    let requests = tokio::spawn(async move {
        let mut bytes = 0_u64;
        let mut request_sequence = 0_u64;
        let mut produce_sequence = 0_u64;
        while let Some(payload) = read_frame(&mut client_read, max_frame_bytes).await? {
            bytes += payload.len() as u64 + 4;
            request_sequence += 1;
            match decode_request(&payload) {
                Ok(decoded) => {
                    let (kind, sequence) = if !replay_supports_api(decoded.api_key) {
                        let reason = format!(
                            "Kafka API {:?} is outside the replay V1 profile",
                            decoded.api_key
                        );
                        request_safe.store(false, Ordering::Release);
                        record_proxy_error(&request_state, &request_context, reason.clone())
                            .await?;
                        (PendingKind::Unsupported(reason), request_sequence)
                    } else {
                        match decoded.api_key {
                            ApiKey::Produce => match records_from_produce(&decoded.request) {
                                Ok(records) => {
                                    let sequence = produce_sequence + 1;
                                    produce_sequence += records.len() as u64;
                                    (PendingKind::Produce(records), sequence)
                                }
                                Err(error) => {
                                    request_safe.store(false, Ordering::Release);
                                    record_proxy_error(
                                        &request_state,
                                        &request_context,
                                        format!("unsupported Kafka Produce: {error}"),
                                    )
                                    .await?;
                                    (
                                        PendingKind::Unsupported(error.to_string()),
                                        request_sequence,
                                    )
                                }
                            },
                            ApiKey::Fetch => (PendingKind::Fetch, request_sequence),
                            _ => (PendingKind::Control, request_sequence),
                        }
                    };
                    let request = PendingRequest {
                        api_key: decoded.api_key,
                        api_version: decoded.header.request_api_version,
                        sequence,
                        started: Instant::now(),
                        kind,
                    };
                    if request_pending
                        .lock()
                        .await
                        .insert(decoded.header.correlation_id, request)
                        .is_some()
                    {
                        request_safe.store(false, Ordering::Release);
                        record_proxy_error(
                            &request_state,
                            &request_context,
                            format!(
                                "duplicate in-flight Kafka correlation id {}",
                                decoded.header.correlation_id
                            ),
                        )
                        .await?;
                    }
                }
                Err(error) => {
                    request_safe.store(false, Ordering::Release);
                    record_proxy_error(
                        &request_state,
                        &request_context,
                        format!("Kafka request parse failed: {error}"),
                    )
                    .await?;
                }
            }
            write_frame(&mut upstream_write, &payload).await?;
        }
        let _ = upstream_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
    });

    let response_pending = pending.clone();
    let response_safe = replay_safe.clone();
    let response_state = state.clone();
    let response_context = context.clone();
    let responses = tokio::spawn(async move {
        let mut bytes = 0_u64;
        let mut delivery_sequence = 0_u64;
        while let Some(payload) = read_frame(&mut upstream_read, max_frame_bytes).await? {
            bytes += payload.len() as u64 + 4;
            let correlation_id = response_correlation_id(&payload)?;
            let request = response_pending.lock().await.remove(&correlation_id);
            match request {
                Some(request) => {
                    let PendingRequest {
                        api_key,
                        api_version,
                        sequence,
                        started,
                        kind,
                    } = request;
                    match kind {
                        PendingKind::Produce(records) => {
                            match decode_response(&payload, api_key, api_version) {
                                Ok(decoded) => {
                                    record_produce_results(
                                        &response_state,
                                        connection_id,
                                        &response_context,
                                        ProduceCompletion {
                                            sequence,
                                            api_version,
                                            started,
                                            records,
                                            response: decoded.response,
                                        },
                                    )
                                    .await?;
                                }
                                Err(error) => {
                                    response_safe.store(false, Ordering::Release);
                                    record_proxy_error(
                                        &response_state,
                                        &response_context,
                                        format!("Kafka Produce response parse failed: {error}"),
                                    )
                                    .await?;
                                }
                            }
                        }
                        PendingKind::Fetch => {
                            match decode_response(&payload, api_key, api_version)
                                .and_then(|decoded| records_from_fetch(&decoded.response))
                            {
                                Ok(records) => {
                                    for record in records {
                                        delivery_sequence += 1;
                                        record_delivery(
                                            &response_state,
                                            connection_id,
                                            delivery_sequence,
                                            &response_context,
                                            api_version,
                                            record,
                                        )
                                        .await?;
                                    }
                                }
                                Err(error) => {
                                    response_safe.store(false, Ordering::Release);
                                    record_proxy_error(
                                        &response_state,
                                        &response_context,
                                        format!("Kafka Fetch response parse failed: {error}"),
                                    )
                                    .await?;
                                }
                            }
                        }
                        PendingKind::Unsupported(reason) => {
                            let _ = reason;
                        }
                        PendingKind::Control => {}
                    }
                }
                None => {
                    response_safe.store(false, Ordering::Release);
                    record_proxy_error(
                        &response_state,
                        &response_context,
                        format!(
                            "Kafka response correlation id {correlation_id} has no pending request"
                        ),
                    )
                    .await?;
                }
            }
            write_frame(&mut client_write, &payload).await?;
        }
        let _ = client_write.shutdown().await;
        Ok::<u64, anyhow::Error>(bytes)
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
    if !pending.lock().await.is_empty() {
        replay_safe.store(false, Ordering::Release);
        record_proxy_error(
            &state,
            &context,
            "Kafka connection closed with incomplete requests".to_string(),
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

async fn record_produce_results(
    state: &AppState,
    connection_id: Uuid,
    context: &KafkaConnectionContext,
    completion: ProduceCompletion,
) -> Result<()> {
    let ResponseKind::Produce(response) = completion.response else {
        return Err(anyhow!("Kafka Produce response decoded as another API"));
    };
    for (index, record) in completion.records.into_iter().enumerate() {
        let error_code = response
            .responses
            .iter()
            .find(|topic| topic.name.as_str() == record.topic)
            .and_then(|topic| {
                topic
                    .partition_responses
                    .iter()
                    .find(|partition| partition.index == record.partition)
            })
            .map(|partition| partition.error_code);
        let replay_safe = error_code == Some(0);
        let warnings = if replay_safe {
            Vec::new()
        } else {
            vec![format!(
                "Kafka Produce result is unsupported for replay: error_code={error_code:?}"
            )]
        };
        let captured = capture_record(record, state.config().recording.max_body_bytes);
        let replay_safe = replay_safe && captured.replay_safe;
        record_event(
            state,
            RecorderEvent::KafkaProduce(KafkaProduceEvent {
                id: Uuid::new_v4(),
                connection_id,
                sequence: completion.sequence + index as u64,
                timestamp: Utc::now(),
                client_addr: context.client_addr.clone(),
                client_process: context.client_process.clone(),
                target_host: context.target_host.clone(),
                target_port: context.target_port,
                target_addr: context.target_addr.clone(),
                upstream_addr: context.upstream_addr.clone(),
                api_version: completion.api_version,
                topic: captured.topic,
                key: captured.key,
                headers: captured.headers,
                value: captured.value,
                result: if error_code == Some(0) {
                    "accepted".to_string()
                } else {
                    "error".to_string()
                },
                duration_ms: completion.started.elapsed().as_millis(),
                replay_safe,
                parse_warnings: warnings,
            }),
        )
        .await?;
    }
    Ok(())
}

async fn record_delivery(
    state: &AppState,
    connection_id: Uuid,
    sequence: u64,
    context: &KafkaConnectionContext,
    api_version: i16,
    record: KafkaRecord,
) -> Result<()> {
    let timestamp = record.timestamp_ms;
    let captured = capture_record(record, state.config().recording.max_body_bytes);
    record_event(
        state,
        RecorderEvent::KafkaDelivery(KafkaDeliveryEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence,
            timestamp: Utc::now(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            upstream_addr: context.upstream_addr.clone(),
            api_version,
            topic: captured.topic,
            key: captured.key,
            headers: captured.headers,
            value: captured.value,
            message_timestamp_ms: timestamp,
            replay_safe: captured.replay_safe,
            parse_warnings: Vec::new(),
        }),
    )
    .await
}

struct CapturedRecord {
    topic: String,
    key: Option<crate::recorder::BodyCapture>,
    headers: Vec<KafkaHeaderCapture>,
    value: Option<crate::recorder::BodyCapture>,
    replay_safe: bool,
}

fn capture_record(record: KafkaRecord, max_body_bytes: usize) -> CapturedRecord {
    let key = record.key.map(|value| capture_body(&value, max_body_bytes));
    let value = record
        .value
        .map(|value| capture_body(&value, max_body_bytes));
    let headers = record
        .headers
        .into_iter()
        .map(|header| KafkaHeaderCapture {
            name: header.name,
            value: header
                .value
                .map(|value| capture_body(&value, max_body_bytes)),
        })
        .collect::<Vec<_>>();
    let replay_safe = key.as_ref().is_none_or(|value| !value.truncated)
        && value.as_ref().is_none_or(|value| !value.truncated)
        && headers
            .iter()
            .all(|header| header.value.as_ref().is_none_or(|value| !value.truncated));
    CapturedRecord {
        topic: record.topic,
        key,
        headers,
        value,
        replay_safe,
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
            client_process: context.client_process.clone(),
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
            timestamp: Utc::now(),
            protocol: "kafka".to_string(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target: Some(context.target_addr.clone()),
            error,
        }),
    )
    .await
}

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.recorder().record(event.clone()).await?;
    state.record_dependency_if_relevant(&event).await;
    Ok(())
}

#[cfg(test)]
mod tests;
