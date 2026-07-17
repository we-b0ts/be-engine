use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::Deserialize;

use crate::kafka::{KafkaHeader, KafkaRecord};

use super::super::{
    ReplayProtocol, ReplaySource, ReplayTarget, TargetKey, push_success_detail,
    register_replay_target,
};
use super::report::{
    KafkaMatchedReport, KafkaProtocolReport, KafkaRequestReport, KafkaUnusedReport,
};

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaConnection {
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaProduce {
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) topic: String,
    pub(super) key: Option<RecordedCapture>,
    #[serde(default)]
    pub(super) headers: Vec<RecordedKafkaHeader>,
    pub(super) value: Option<RecordedCapture>,
    pub(super) result: String,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaDelivery {
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) topic: String,
    pub(super) key: Option<RecordedCapture>,
    #[serde(default)]
    pub(super) headers: Vec<RecordedKafkaHeader>,
    pub(super) value: Option<RecordedCapture>,
    pub(super) message_timestamp_ms: i64,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedKafkaHeader {
    name: String,
    value: Option<RecordedCapture>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedCapture {
    encoding: String,
    data: String,
    truncated: bool,
}

impl RecordedCapture {
    fn decode(&self) -> Result<Bytes> {
        if self.truncated {
            return Err(anyhow!("Kafka replay capture is truncated"));
        }
        let bytes = match self.encoding.as_str() {
            "base64" => STANDARD
                .decode(&self.data)
                .context("failed to decode Kafka base64 capture")?,
            "utf8" => self.data.as_bytes().to_vec(),
            other => return Err(anyhow!("unsupported Kafka capture encoding {other}")),
        };
        Ok(Bytes::from(bytes))
    }
}

#[derive(Debug, Clone)]
struct ReplayKafkaProduce {
    source: ReplaySource,
    case_id: Option<String>,
    target: TargetKey,
    record: KafkaRecord,
    consumed: bool,
}

#[derive(Debug, Clone)]
struct ReplayKafkaDelivery {
    source: ReplaySource,
    case_id: Option<String>,
    target: TargetKey,
    record: KafkaRecord,
    consumed: bool,
}

#[derive(Debug, Default)]
pub(in crate::replay) struct KafkaReplayState {
    produces: Vec<ReplayKafkaProduce>,
    deliveries: Vec<ReplayKafkaDelivery>,
    pub(super) events: KafkaReplayEvents,
}

#[derive(Debug, Default)]
pub(super) struct KafkaReplayEvents {
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<KafkaMatchedReport>,
    unmatched: Vec<KafkaRequestReport>,
    unsupported: Vec<KafkaRequestReport>,
    unsafe_events: Vec<KafkaRequestReport>,
}

impl KafkaReplayState {
    pub(in crate::replay) fn register_connection(
        &mut self,
        record: RecordedKafkaConnection,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        let target = TargetKey {
            host: record.target_host,
            port: record.target_port,
        };
        if !record.replay_safe {
            return Err(anyhow!(
                "unsafe Kafka connection metadata for {}:{}",
                target.host,
                target.port
            ));
        }
        register_replay_target(targets, &target, ReplayProtocol::Kafka)
    }

    pub(in crate::replay) fn register_produce(
        &mut self,
        record: RecordedKafkaProduce,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe || record.result != "accepted" {
            return Err(anyhow!(
                "Kafka produce for topic {} is not safe successful-path evidence",
                record.topic
            ));
        }
        let target = TargetKey {
            host: record.target_host,
            port: record.target_port,
        };
        register_replay_target(targets, &target, ReplayProtocol::Kafka)?;
        let semantic = decode_record(record.topic, record.key, record.headers, record.value, 0)?;
        self.produces.push(ReplayKafkaProduce {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            target,
            record: semantic,
            consumed: false,
        });
        Ok(())
    }

    pub(in crate::replay) fn register_delivery(
        &mut self,
        record: RecordedKafkaDelivery,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe {
            return Err(anyhow!(
                "Kafka delivery for topic {} is not replay safe",
                record.topic
            ));
        }
        let target = TargetKey {
            host: record.target_host,
            port: record.target_port,
        };
        register_replay_target(targets, &target, ReplayProtocol::Kafka)?;
        let semantic = decode_record(
            record.topic,
            record.key,
            record.headers,
            record.value,
            record.message_timestamp_ms,
        )?;
        self.deliveries.push(ReplayKafkaDelivery {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            target,
            record: semantic,
            consumed: false,
        });
        Ok(())
    }

    pub(super) fn topics(&self) -> BTreeSet<String> {
        self.produces
            .iter()
            .map(|exchange| exchange.record.topic.clone())
            .chain(
                self.deliveries
                    .iter()
                    .map(|exchange| exchange.record.topic.clone()),
            )
            .collect()
    }

    pub(super) fn match_produce(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        records: &[KafkaRecord],
    ) -> bool {
        let mut selected = Vec::with_capacity(records.len());
        for record in records {
            let Some(index) = self
                .produces
                .iter()
                .enumerate()
                .find_map(|(index, exchange)| {
                    (!exchange.consumed
                        && scope_matches(
                            active_case_id,
                            exchange.source,
                            exchange.case_id.as_deref(),
                        )
                        && &exchange.target == target
                        && semantic_record_matches(&exchange.record, record)
                        && !selected.contains(&index))
                    .then_some(index)
                })
            else {
                self.events.unmatched.push(KafkaRequestReport {
                    case_id: active_case_id.map(ToOwned::to_owned),
                    target: target.clone(),
                    operation: "produce".to_string(),
                    topic: Some(record.topic.clone()),
                    reason: "no recorded Kafka produce matched topic/key/headers/value".to_string(),
                });
                return false;
            };
            selected.push(index);
        }
        for index in selected {
            let exchange = &mut self.produces[index];
            exchange.consumed = true;
            push_success_detail(
                &mut self.events.matched_count,
                &mut self.events.matched,
                KafkaMatchedReport {
                    case_id: exchange.case_id.clone(),
                    source: exchange.source,
                    index,
                    target: target.clone(),
                    operation: "produce".to_string(),
                    topic: exchange.record.topic.clone(),
                },
            );
        }
        true
    }

    pub(super) fn take_deliveries(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        requested_topics: &BTreeSet<String>,
    ) -> Vec<KafkaRecord> {
        let selected = self
            .deliveries
            .iter()
            .enumerate()
            .filter_map(|(index, exchange)| {
                (!exchange.consumed
                    && scope_matches(active_case_id, exchange.source, exchange.case_id.as_deref())
                    && &exchange.target == target
                    && requested_topics.contains(&exchange.record.topic))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let mut records = Vec::with_capacity(selected.len());
        for index in selected {
            let exchange = &mut self.deliveries[index];
            exchange.consumed = true;
            records.push(exchange.record.clone());
            push_success_detail(
                &mut self.events.matched_count,
                &mut self.events.matched,
                KafkaMatchedReport {
                    case_id: exchange.case_id.clone(),
                    source: exchange.source,
                    index,
                    target: target.clone(),
                    operation: "delivery".to_string(),
                    topic: exchange.record.topic.clone(),
                },
            );
        }
        records
    }

    pub(super) fn record_unsupported(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        operation: String,
        reason: String,
    ) {
        self.events.unsupported.push(KafkaRequestReport {
            case_id: active_case_id.map(ToOwned::to_owned),
            target: target.clone(),
            operation,
            topic: None,
            reason,
        });
    }

    pub(in crate::replay) fn snapshot(&self) -> KafkaProtocolReport {
        KafkaProtocolReport {
            connections: self.events.connections,
            matched_count: self.events.matched_count,
            matched: self.events.matched.clone(),
            unmatched: self.events.unmatched.clone(),
            unsupported: self.events.unsupported.clone(),
            unsafe_events: self.events.unsafe_events.clone(),
            unused_case: self.unused(ReplaySource::Case),
            unused_bootstrap: self.unused(ReplaySource::Bootstrap),
        }
    }

    fn unused(&self, source: ReplaySource) -> Vec<KafkaUnusedReport> {
        self.produces
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
            .map(|(index, exchange)| KafkaUnusedReport {
                index,
                case_id: exchange.case_id.clone(),
                source,
                target: exchange.target.clone(),
                operation: "produce".to_string(),
                topic: exchange.record.topic.clone(),
            })
            .chain(
                self.deliveries
                    .iter()
                    .enumerate()
                    .filter(|(_, exchange)| exchange.source == source && !exchange.consumed)
                    .map(|(index, exchange)| KafkaUnusedReport {
                        index,
                        case_id: exchange.case_id.clone(),
                        source,
                        target: exchange.target.clone(),
                        operation: "delivery".to_string(),
                        topic: exchange.record.topic.clone(),
                    }),
            )
            .collect()
    }
}

fn decode_record(
    topic: String,
    key: Option<RecordedCapture>,
    headers: Vec<RecordedKafkaHeader>,
    value: Option<RecordedCapture>,
    timestamp_ms: i64,
) -> Result<KafkaRecord> {
    Ok(KafkaRecord {
        topic,
        partition: 0,
        timestamp_ms,
        key: key.as_ref().map(RecordedCapture::decode).transpose()?,
        headers: headers
            .into_iter()
            .map(|header| {
                Ok(KafkaHeader {
                    name: header.name,
                    value: header
                        .value
                        .as_ref()
                        .map(RecordedCapture::decode)
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        value: value.as_ref().map(RecordedCapture::decode).transpose()?,
    })
}

fn semantic_record_matches(expected: &KafkaRecord, actual: &KafkaRecord) -> bool {
    expected.topic == actual.topic
        && expected.key == actual.key
        && expected.headers == actual.headers
        && expected.value == actual.value
}

fn scope_matches(
    active_case_id: Option<&str>,
    source: ReplaySource,
    case_id: Option<&str>,
) -> bool {
    match active_case_id {
        Some(active) => source == ReplaySource::Case && case_id == Some(active),
        None => source == ReplaySource::Bootstrap,
    }
}
