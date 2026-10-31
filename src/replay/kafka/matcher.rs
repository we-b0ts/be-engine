use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use serde::Deserialize;
use uuid::Uuid;

use crate::dependency::DependencyExchangeOutcome;
use crate::kafka::{KafkaHeader, KafkaRecord};

use super::super::{
    CaseExchangeIndex, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol, ReplaySource,
    ReplayTarget, SuccessDetailBudget, TargetKey, push_success_detail, register_replay_target,
};
use super::report::{
    KafkaMatchedReport, KafkaProtocolReport, KafkaRequestReport, KafkaUnusedReport,
};
mod evidence;
mod finite_inventory;
pub(in crate::replay) use finite_inventory::FiniteExchange;
mod report_inventory;

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaConnection {
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaProduce {
    pub(super) connection_id: Uuid,
    #[serde(default, rename = "sequence")]
    pub(super) record_sequence: Option<u64>,
    pub(super) request_sequence: u64,
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) topic: String,
    pub(super) key: Option<RecordedCapture>,
    #[serde(default)]
    pub(super) headers: Vec<RecordedKafkaHeader>,
    pub(super) value: Option<RecordedCapture>,
    pub(super) result: String,
    pub(super) outcome: DependencyExchangeOutcome,
    pub(super) duration_ms: u64,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaFetch {
    pub(super) connection_id: Uuid,
    pub(super) sequence: u64,
    pub(super) target_host: String,
    pub(super) target_port: u16,
    pub(super) topics: Vec<String>,
    pub(super) outcome: DependencyExchangeOutcome,
    pub(super) duration_ms: u64,
    pub(super) replay_safe: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(in crate::replay) struct RecordedKafkaDelivery {
    pub(super) connection_id: Uuid,
    #[serde(default)]
    pub(super) sequence: Option<u64>,
    pub(super) fetch_sequence: u64,
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
    record_sequence: Option<u64>,
    evidence: Option<crate::dependency_index::RecordRef>,
    source: ReplaySource,
    case_id: Option<String>,
    target: TargetKey,
    connection_id: Uuid,
    request_sequence: u64,
    record: KafkaRecord,
    timing: ReplayExchangeTiming,
    status: ReplayExchangeStatus,
}

#[derive(Debug, Clone)]
struct ReplayKafkaFetch {
    source: ReplaySource,
    case_id: Option<String>,
    target: TargetKey,
    connection_id: Uuid,
    sequence: u64,
    topics: BTreeSet<String>,
    timing: ReplayExchangeTiming,
    status: ReplayExchangeStatus,
}

#[derive(Debug, Clone)]
struct ReplayKafkaDelivery {
    sequence: Option<u64>,
    evidence: Option<crate::dependency_index::RecordRef>,
    source: ReplaySource,
    case_id: Option<String>,
    target: TargetKey,
    connection_id: Uuid,
    fetch_sequence: u64,
    record: KafkaRecord,
    status: ReplayExchangeStatus,
}

#[derive(Debug)]
pub(super) struct KafkaProduceReservation {
    indices: Vec<usize>,
    case_id: Option<String>,
    pub(super) timing: ReplayExchangeTiming,
}

#[derive(Debug)]
pub(super) struct KafkaFetchReservation {
    fetch_index: usize,
    delivery_indices: Vec<usize>,
    case_id: Option<String>,
    pub(super) records: Vec<KafkaRecord>,
    pub(super) timing: ReplayExchangeTiming,
}

#[derive(Debug, Default)]
pub(in crate::replay) struct KafkaReplayState {
    produces: Vec<ReplayKafkaProduce>,
    produce_case_index: CaseExchangeIndex,
    fetches: Vec<ReplayKafkaFetch>,
    fetch_case_index: CaseExchangeIndex,
    deliveries: Vec<ReplayKafkaDelivery>,
    delivery_case_index: CaseExchangeIndex,
    pub(in crate::replay) events: KafkaReplayEvents,
}

#[derive(Debug, Default)]
pub(in crate::replay) struct KafkaReplayEvents {
    global_report: crate::replay::report::global_evidence::regular_usage::Usage,
    dirty_case_ids: BTreeSet<String>,
    pub(super) connections: usize,
    matched_count: usize,
    matched: Vec<KafkaMatchedReport>,
    pub(in crate::replay) matched_details: SuccessDetailBudget,
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
        let expected_result = match record.outcome {
            DependencyExchangeOutcome::Response => "accepted",
            DependencyExchangeOutcome::ClientTerminated => "client_terminated",
            DependencyExchangeOutcome::NoResponse => "sent",
            DependencyExchangeOutcome::Terminated(termination) => match termination.side {
                crate::dependency::TerminationSide::Client => "client_terminated",
                crate::dependency::TerminationSide::Server => "server_terminated",
                crate::dependency::TerminationSide::Engine => {
                    return Err(anyhow!(
                        "engine cleanup cannot be Kafka termination evidence"
                    ));
                }
            },
        };
        if !record.replay_safe || record.result != expected_result {
            return Err(anyhow!(
                "Kafka produce for topic {} is not replay-safe {:?} evidence",
                record.topic,
                record.outcome
            ));
        }
        anyhow::ensure!(
            !record.outcome.termination().is_some_and(
                |termination| termination.scope == crate::dependency::TerminationScope::Stream
            ),
            "Kafka native termination cannot have stream scope"
        );
        let target = TargetKey {
            host: record.target_host,
            port: record.target_port,
        };
        register_replay_target(targets, &target, ReplayProtocol::Kafka)?;
        let semantic = decode_record(record.topic, record.key, record.headers, record.value, 0)?;
        let exchange_index = self.produces.len();
        self.produce_case_index
            .register(source, case_id, exchange_index);
        self.produces.push(ReplayKafkaProduce {
            record_sequence: record.record_sequence,
            evidence: None,
            source,
            case_id: case_id.map(ToOwned::to_owned),
            target,
            connection_id: record.connection_id,
            request_sequence: record.request_sequence,
            record: semantic,
            timing: ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome),
            status: ReplayExchangeStatus::Available,
        });
        Ok(())
    }

    pub(in crate::replay) fn register_fetch(
        &mut self,
        record: RecordedKafkaFetch,
        source: ReplaySource,
        case_id: Option<&str>,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        if !record.replay_safe || record.outcome == DependencyExchangeOutcome::NoResponse {
            return Err(anyhow!("Kafka fetch is not replay-safe response evidence"));
        }
        anyhow::ensure!(
            !record.outcome.termination().is_some_and(
                |termination| termination.scope == crate::dependency::TerminationScope::Stream
            ),
            "Kafka native termination cannot have stream scope"
        );
        let target = TargetKey {
            host: record.target_host,
            port: record.target_port,
        };
        register_replay_target(targets, &target, ReplayProtocol::Kafka)?;
        let exchange_index = self.fetches.len();
        self.fetch_case_index
            .register(source, case_id, exchange_index);
        self.fetches.push(ReplayKafkaFetch {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            target,
            connection_id: record.connection_id,
            sequence: record.sequence,
            topics: record.topics.into_iter().collect(),
            timing: ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome),
            status: ReplayExchangeStatus::Available,
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
        let exchange_index = self.deliveries.len();
        self.delivery_case_index
            .register(source, case_id, exchange_index);
        self.deliveries.push(ReplayKafkaDelivery {
            sequence: record.sequence,
            evidence: None,
            source,
            case_id: case_id.map(ToOwned::to_owned),
            target,
            connection_id: record.connection_id,
            fetch_sequence: record.fetch_sequence,
            record: semantic,
            status: ReplayExchangeStatus::Available,
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

    pub(super) fn reserve_produce(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        records: &[KafkaRecord],
        no_response: bool,
    ) -> Option<KafkaProduceReservation> {
        let first = records.first()?;
        let candidates = self
            .produces
            .iter()
            .filter(|exchange| {
                exchange.status.is_available()
                    && scope_matches(active_case_id, exchange.source, exchange.case_id.as_deref())
                    && &exchange.target == target
                    && (exchange.timing.outcome() == DependencyExchangeOutcome::NoResponse)
                        == no_response
                    && exchange.matches(first)
            })
            .map(|exchange| (exchange.connection_id, exchange.request_sequence))
            .collect::<Vec<_>>();
        for (connection_id, request_sequence) in candidates {
            let group = self
                .produces
                .iter()
                .enumerate()
                .filter_map(|(index, exchange)| {
                    (exchange.status.is_available()
                        && exchange.connection_id == connection_id
                        && exchange.request_sequence == request_sequence
                        && scope_matches(
                            active_case_id,
                            exchange.source,
                            exchange.case_id.as_deref(),
                        )
                        && &exchange.target == target)
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            if group.len() != records.len() {
                continue;
            }
            let mut selected = Vec::with_capacity(records.len());
            for record in records {
                let Some(index) = group.iter().copied().find(|index| {
                    !selected.contains(index) && self.produces[*index].matches(record)
                }) else {
                    selected.clear();
                    break;
                };
                selected.push(index);
            }
            if selected.len() != records.len() {
                continue;
            }
            let timing = self.produces[selected[0]].timing;
            if selected
                .iter()
                .any(|index| self.produces[*index].timing.outcome() != timing.outcome())
            {
                continue;
            }
            let status = reservation_status(timing.outcome());
            for index in &selected {
                self.produces[*index].status = status;
            }
            return Some(KafkaProduceReservation {
                indices: selected,
                case_id: active_case_id.map(ToOwned::to_owned),
                timing,
            });
        }
        if let Some(case_id) = active_case_id {
            self.events.dirty_case_ids.insert(case_id.to_string());
        }
        self.events.unmatched.push(KafkaRequestReport {
            case_id: active_case_id.map(ToOwned::to_owned),
            target: target.clone(),
            operation: "produce".to_string(),
            topic: Some(first.topic.clone()),
            reason: "no recorded Kafka produce request matched topic/key/headers/value".to_string(),
        });
        None
    }

    pub(super) fn commit_produce(&mut self, reservation: KafkaProduceReservation) {
        let case_id = reservation.case_id;
        for index in reservation.indices {
            let exchange = &mut self.produces[index];
            exchange.status = ReplayExchangeStatus::Consumed;
            push_success_detail(
                &mut self.events.matched_count,
                &mut self.events.matched,
                &mut self.events.matched_details,
                case_id.as_deref(),
                |target_event_index| KafkaMatchedReport {
                    case_id: case_id.clone(),
                    source: exchange.source,
                    index,
                    target: exchange.target.clone(),
                    operation: "produce".to_string(),
                    topic: exchange.record.topic.clone(),
                    target_event_index: Some(target_event_index),
                },
            );
            self.refresh_global_report(0, index);
        }
    }

    pub(super) fn fail_produce(
        &mut self,
        reservation: KafkaProduceReservation,
        target: &TargetKey,
        reason: String,
    ) {
        for index in reservation.indices {
            self.produces[index].status = ReplayExchangeStatus::Failed;
            self.refresh_global_report(0, index);
        }
        self.record_unsafe(target, "produce", reason);
    }

    pub(super) fn reserve_fetch(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        requested_topics: &BTreeSet<String>,
    ) -> Option<KafkaFetchReservation> {
        let fetch_index = self.fetches.iter().position(|exchange| {
            exchange.status.is_available()
                && scope_matches(active_case_id, exchange.source, exchange.case_id.as_deref())
                && &exchange.target == target
                && &exchange.topics == requested_topics
        })?;
        let fetch = &self.fetches[fetch_index];
        let delivery_indices = self
            .deliveries
            .iter()
            .enumerate()
            .filter_map(|(index, delivery)| {
                (delivery.status.is_available()
                    && delivery.source == fetch.source
                    && delivery.case_id == fetch.case_id
                    && delivery.target == fetch.target
                    && delivery.connection_id == fetch.connection_id
                    && delivery.fetch_sequence == fetch.sequence)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let records = delivery_indices
            .iter()
            .map(|index| self.deliveries[*index].materialize())
            .collect::<Result<Vec<_>>>();
        let records = match records {
            Ok(records) => records,
            Err(error) => {
                self.record_unsafe(
                    target,
                    "fetch",
                    format!("Kafka delivery evidence unavailable: {error:#}"),
                );
                return None;
            }
        };
        let timing = fetch.timing;
        let status = reservation_status(timing.outcome());
        self.fetches[fetch_index].status = status;
        for index in &delivery_indices {
            self.deliveries[*index].status = status;
        }
        Some(KafkaFetchReservation {
            fetch_index,
            delivery_indices,
            case_id: active_case_id.map(ToOwned::to_owned),
            records,
            timing,
        })
    }

    pub(super) fn commit_fetch(&mut self, reservation: KafkaFetchReservation) {
        let case_id = reservation.case_id;
        let fetch = &mut self.fetches[reservation.fetch_index];
        fetch.status = ReplayExchangeStatus::Consumed;
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            &mut self.events.matched_details,
            case_id.as_deref(),
            |target_event_index| KafkaMatchedReport {
                case_id: case_id.clone(),
                source: fetch.source,
                index: reservation.fetch_index,
                target: fetch.target.clone(),
                operation: "fetch".to_string(),
                topic: fetch.topics.iter().cloned().collect::<Vec<_>>().join(","),
                target_event_index: Some(target_event_index),
            },
        );
        self.refresh_global_report(1, reservation.fetch_index);
        for index in reservation.delivery_indices {
            let delivery = &mut self.deliveries[index];
            delivery.status = ReplayExchangeStatus::Consumed;
            push_success_detail(
                &mut self.events.matched_count,
                &mut self.events.matched,
                &mut self.events.matched_details,
                case_id.as_deref(),
                |target_event_index| KafkaMatchedReport {
                    case_id: case_id.clone(),
                    source: delivery.source,
                    index,
                    target: delivery.target.clone(),
                    operation: "delivery".to_string(),
                    topic: delivery.record.topic.clone(),
                    target_event_index: Some(target_event_index),
                },
            );
            self.refresh_global_report(2, index);
        }
    }

    pub(super) fn fail_fetch(
        &mut self,
        reservation: KafkaFetchReservation,
        target: &TargetKey,
        reason: String,
    ) {
        self.fetches[reservation.fetch_index].status = ReplayExchangeStatus::Failed;
        self.refresh_global_report(1, reservation.fetch_index);
        for index in reservation.delivery_indices {
            self.deliveries[index].status = ReplayExchangeStatus::Failed;
            self.refresh_global_report(2, index);
        }
        self.record_unsafe(target, "fetch", reason);
    }

    pub(super) fn record_unsupported(
        &mut self,
        active_case_id: Option<&str>,
        target: &TargetKey,
        operation: String,
        reason: String,
    ) {
        if let Some(case_id) = active_case_id {
            self.events.dirty_case_ids.insert(case_id.to_string());
        }
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
            unused_global_count: Some(self.global_unused_count()),
            unused_global: self.unused(ReplaySource::Startup),
        }
    }

    pub(in crate::replay) fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.events.dirty_case_ids.contains(case)
    }

    pub(in crate::replay) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.produce_case_index.any(case_id, |index| {
                self.produces
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
            || self.fetch_case_index.any(case_id, |index| {
                self.fetches
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
            || self.delivery_case_index.any(case_id, |index| {
                self.deliveries
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
    }

    pub(in crate::replay) fn has_in_flight(&self) -> bool {
        self.in_flight(None)
    }

    pub(in crate::replay) fn has_case_in_flight(&self) -> bool {
        self.in_flight(Some(ReplaySource::Case))
    }

    fn in_flight(&self, scope: Option<ReplaySource>) -> bool {
        let pending = |source, status| {
            scope.is_none_or(|scope| source == scope)
                && matches!(
                    status,
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        };
        self.produces
            .iter()
            .any(|entry| pending(entry.source, entry.status))
            || self
                .fetches
                .iter()
                .any(|entry| pending(entry.source, entry.status))
            || self
                .deliveries
                .iter()
                .any(|entry| pending(entry.source, entry.status))
    }

    fn record_unsafe(&mut self, target: &TargetKey, operation: &str, reason: String) {
        self.events.unsafe_events.push(KafkaRequestReport {
            case_id: None,
            target: target.clone(),
            operation: operation.to_string(),
            topic: None,
            reason,
        });
    }

    fn unused_iter(&self, source: ReplaySource) -> impl Iterator<Item = KafkaUnusedReport> + '_ {
        self.produces
            .iter()
            .enumerate()
            .filter(move |(_, exchange)| {
                exchange.source.matches_scope(source) && !exchange.status.is_consumed()
            })
            .map(move |(index, exchange)| KafkaUnusedReport {
                index,
                case_id: exchange.case_id.clone(),
                source,
                target: exchange.target.clone(),
                operation: "produce".to_string(),
                topic: exchange.record.topic.clone(),
            })
            .chain(
                self.fetches
                    .iter()
                    .enumerate()
                    .filter(move |(_, exchange)| {
                        exchange.source.matches_scope(source) && !exchange.status.is_consumed()
                    })
                    .map(move |(index, exchange)| KafkaUnusedReport {
                        index,
                        case_id: exchange.case_id.clone(),
                        source,
                        target: exchange.target.clone(),
                        operation: "fetch".to_string(),
                        topic: exchange
                            .topics
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(","),
                    }),
            )
            .chain(
                self.deliveries
                    .iter()
                    .enumerate()
                    .filter(move |(_, exchange)| {
                        exchange.source.matches_scope(source) && !exchange.status.is_consumed()
                    })
                    .map(move |(index, exchange)| KafkaUnusedReport {
                        index,
                        case_id: exchange.case_id.clone(),
                        source,
                        target: exchange.target.clone(),
                        operation: "delivery".to_string(),
                        topic: exchange.record.topic.clone(),
                    }),
            )
    }

    fn unused(&self, source: ReplaySource) -> Vec<KafkaUnusedReport> {
        self.unused_iter(source)
            .take(if source.is_run_owned() {
                100
            } else {
                usize::MAX
            })
            .collect()
    }
}

fn reservation_status(outcome: DependencyExchangeOutcome) -> ReplayExchangeStatus {
    if outcome.is_client_terminated() {
        ReplayExchangeStatus::AwaitingClientTermination
    } else {
        ReplayExchangeStatus::Responding
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
        None => source.is_run_owned(),
    }
}

impl KafkaReplayState {
    pub(in crate::replay) fn release_consumed_payloads(
        &mut self,
        cases: &BTreeMap<String, crate::replay::ReplayCase>,
    ) {
        for exchange in &mut self.produces {
            if exchange.source == ReplaySource::Case
                && exchange.status.is_consumed()
                && exchange.case_id.as_ref().is_some_and(|id| {
                    cases
                        .get(id)
                        .is_some_and(|case| case.status == crate::replay::ReplayCaseStatus::Ended)
                })
            {
                exchange.record.value = None;
                exchange.record.key = None;
                exchange.record.headers = Vec::new();
            }
        }
        for exchange in &mut self.deliveries {
            if exchange.source == ReplaySource::Case
                && exchange.status.is_consumed()
                && exchange.case_id.as_ref().is_some_and(|id| {
                    cases
                        .get(id)
                        .is_some_and(|case| case.status == crate::replay::ReplayCaseStatus::Ended)
                })
            {
                exchange.record.value = None;
                exchange.record.headers = Vec::new();
            }
        }
    }
}
