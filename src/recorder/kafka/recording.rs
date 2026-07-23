use std::time::Instant;

use anyhow::{Result, anyhow};
use chrono::Utc;
use kafka_protocol::messages::ResponseKind;
use uuid::Uuid;

use super::KafkaConnectionContext;
use crate::AppState;
use crate::dependency::DependencyExchangeOutcome;
use crate::kafka::KafkaRecord;
use crate::recorder::{
    KafkaDeliveryEvent, KafkaFetchEvent, KafkaHeaderCapture, KafkaProduceEvent, RecorderEvent,
    capture_body,
};

pub(super) struct ProduceCompletion {
    pub(super) request_sequence: u64,
    pub(super) record_sequence: u64,
    pub(super) api_version: i16,
    pub(super) started: Instant,
    pub(super) records: Vec<KafkaRecord>,
    pub(super) response: Option<ResponseKind>,
    pub(super) outcome: DependencyExchangeOutcome,
}

pub(super) struct FetchCompletion {
    pub(super) sequence: u64,
    pub(super) api_version: i16,
    pub(super) started: Instant,
    pub(super) topics: Vec<String>,
    pub(super) records: Vec<KafkaRecord>,
    pub(super) outcome: DependencyExchangeOutcome,
}

pub(super) async fn record_produce_completion(
    state: &AppState,
    connection_id: Uuid,
    context: &KafkaConnectionContext,
    completion: ProduceCompletion,
) -> Result<()> {
    let duration_ms = completion.started.elapsed().as_millis();
    let response = match (completion.outcome, completion.response) {
        (DependencyExchangeOutcome::Response, Some(ResponseKind::Produce(response))) => {
            Some(response)
        }
        (DependencyExchangeOutcome::Response, Some(_)) => {
            return Err(anyhow!("Kafka Produce response decoded as another API"));
        }
        (DependencyExchangeOutcome::Response, None) => {
            return Err(anyhow!("Kafka Produce response is missing"));
        }
        (_, _) => None,
    };
    for (index, record) in completion.records.into_iter().enumerate() {
        let error_code = response.as_ref().and_then(|response| {
            response
                .responses
                .iter()
                .find(|topic| topic.name.as_str() == record.topic)
                .and_then(|topic| {
                    topic
                        .partition_responses
                        .iter()
                        .find(|partition| partition.index == record.partition)
                })
                .map(|partition| partition.error_code)
        });
        let result = match completion.outcome {
            DependencyExchangeOutcome::Response if error_code == Some(0) => "accepted",
            DependencyExchangeOutcome::Response => "error",
            DependencyExchangeOutcome::ClientTerminated => "client_terminated",
            DependencyExchangeOutcome::NoResponse => "sent",
        };
        let response_replay_safe =
            completion.outcome != DependencyExchangeOutcome::Response || error_code == Some(0);
        let warnings = if response_replay_safe {
            Vec::new()
        } else {
            vec![format!(
                "Kafka Produce result is unsupported for replay: error_code={error_code:?}"
            )]
        };
        let captured = capture_record(record, state.config().recording.max_body_bytes);
        record_event(
            state,
            RecorderEvent::KafkaProduce(KafkaProduceEvent {
                id: Uuid::new_v4(),
                connection_id,
                sequence: completion.record_sequence + index as u64,
                request_sequence: completion.request_sequence,
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
                result: result.to_string(),
                outcome: completion.outcome,
                duration_ms,
                replay_safe: response_replay_safe && captured.replay_safe,
                parse_warnings: warnings,
            }),
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn record_fetch_completion(
    state: &AppState,
    connection_id: Uuid,
    delivery_sequence: &mut u64,
    context: &KafkaConnectionContext,
    completion: FetchCompletion,
) -> Result<()> {
    let duration_ms = completion.started.elapsed().as_millis();
    record_event(
        state,
        RecorderEvent::KafkaFetch(KafkaFetchEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence: completion.sequence,
            timestamp: Utc::now(),
            client_addr: context.client_addr.clone(),
            client_process: context.client_process.clone(),
            target_host: context.target_host.clone(),
            target_port: context.target_port,
            target_addr: context.target_addr.clone(),
            upstream_addr: context.upstream_addr.clone(),
            api_version: completion.api_version,
            topics: completion.topics,
            outcome: completion.outcome,
            duration_ms,
            replay_safe: true,
            parse_warnings: Vec::new(),
        }),
    )
    .await?;
    if completion.outcome != DependencyExchangeOutcome::Response {
        return Ok(());
    }
    for record in completion.records {
        *delivery_sequence += 1;
        record_delivery(
            state,
            connection_id,
            *delivery_sequence,
            completion.sequence,
            context,
            completion.api_version,
            record,
        )
        .await?;
    }
    Ok(())
}

async fn record_delivery(
    state: &AppState,
    connection_id: Uuid,
    sequence: u64,
    fetch_sequence: u64,
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
            fetch_sequence,
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

async fn record_event(state: &AppState, event: RecorderEvent) -> Result<()> {
    state.record_event(event);
    Ok(())
}
