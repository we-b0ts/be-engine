use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use kafka_protocol::indexmap::IndexMap;
use kafka_protocol::messages::api_versions_response::ApiVersion;
use kafka_protocol::messages::fetch_response::{FetchableTopicResponse, PartitionData};
use kafka_protocol::messages::find_coordinator_response::Coordinator;
use kafka_protocol::messages::join_group_response::JoinGroupResponseMember;
use kafka_protocol::messages::list_offsets_response::{
    ListOffsetsPartitionResponse, ListOffsetsTopicResponse,
};
use kafka_protocol::messages::metadata_response::{
    MetadataResponseBroker, MetadataResponsePartition, MetadataResponseTopic,
};
use kafka_protocol::messages::offset_commit_response::{
    OffsetCommitResponsePartition, OffsetCommitResponseTopic,
};
use kafka_protocol::messages::offset_fetch_response::{
    OffsetFetchResponsePartition, OffsetFetchResponseTopic,
};
use kafka_protocol::messages::produce_response::{PartitionProduceResponse, TopicProduceResponse};
use kafka_protocol::messages::{
    ApiVersionsResponse, FetchResponse, FindCoordinatorResponse, HeartbeatResponse,
    JoinGroupResponse, LeaveGroupResponse, ListOffsetsResponse, MetadataResponse,
    OffsetCommitResponse, OffsetFetchResponse, ProduceResponse, RequestKind, ResponseKind,
    SyncGroupResponse, TopicName,
};
use kafka_protocol::protocol::StrBytes;
use kafka_protocol::records::{
    Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};
use tokio::sync::Mutex;

use crate::dependency::DependencyExchangeOutcome;
use crate::kafka::{
    DecodedKafkaRequest, KAFKA_NODE_ID, KafkaRecord, REPLAY_API_VERSIONS, records_from_produce,
};

use super::super::{ReplayExchangeTiming, ReplayState, TargetKey};
use super::matcher::{KafkaFetchReservation, KafkaProduceReservation};

enum KafkaReservation {
    Produce(KafkaProduceReservation),
    Fetch(KafkaFetchReservation),
}

pub(super) struct KafkaReplayPlan {
    response: Option<ResponseKind>,
    timing: Option<ReplayExchangeTiming>,
    reservation: Option<KafkaReservation>,
}

impl KafkaReplayPlan {
    fn response(response: ResponseKind) -> Self {
        Self {
            response: Some(response),
            timing: None,
            reservation: None,
        }
    }

    fn exchange(
        response: Option<ResponseKind>,
        timing: ReplayExchangeTiming,
        reservation: KafkaReservation,
    ) -> Self {
        Self {
            response,
            timing: Some(timing),
            reservation: Some(reservation),
        }
    }

    pub(super) fn response_value(&self) -> Option<&ResponseKind> {
        self.response.as_ref()
    }

    pub(super) fn timing(&self) -> Option<ReplayExchangeTiming> {
        self.timing
    }

    pub(super) async fn commit(self, state: &Arc<Mutex<ReplayState>>) {
        let mut state = state.lock().await;
        match self.reservation {
            Some(KafkaReservation::Produce(reservation)) => {
                state.kafka.commit_produce(reservation);
            }
            Some(KafkaReservation::Fetch(reservation)) => {
                state.kafka.commit_fetch(reservation);
            }
            None => {}
        }
    }

    pub(super) async fn fail(
        self,
        state: &Arc<Mutex<ReplayState>>,
        target: &TargetKey,
        reason: String,
    ) {
        let mut state = state.lock().await;
        match self.reservation {
            Some(KafkaReservation::Produce(reservation)) => {
                state.kafka.fail_produce(reservation, target, reason);
            }
            Some(KafkaReservation::Fetch(reservation)) => {
                state.kafka.fail_fetch(reservation, target, reason);
            }
            None => {}
        }
    }
}

pub(super) async fn response_for(
    decoded: &DecodedKafkaRequest,
    target: &TargetKey,
    state: Arc<Mutex<ReplayState>>,
) -> Result<KafkaReplayPlan> {
    match &decoded.request {
        RequestKind::ApiVersions(_) => Ok(KafkaReplayPlan::response(api_versions_response())),
        RequestKind::Metadata(request) => {
            let topics = state.lock().await.kafka.topics();
            Ok(KafkaReplayPlan::response(metadata_response(
                request, target, topics,
            )))
        }
        RequestKind::Produce(_) => produce_response(decoded, target, state).await,
        RequestKind::Fetch(request) => fetch_response(request, target, state).await,
        RequestKind::ListOffsets(request) => {
            Ok(KafkaReplayPlan::response(list_offsets_response(request)))
        }
        RequestKind::FindCoordinator(request) => Ok(KafkaReplayPlan::response(
            find_coordinator_response(request, target, decoded.header.request_api_version),
        )),
        RequestKind::JoinGroup(request) => {
            Ok(KafkaReplayPlan::response(join_group_response(request)))
        }
        RequestKind::SyncGroup(request) => {
            Ok(KafkaReplayPlan::response(sync_group_response(request)))
        }
        RequestKind::Heartbeat(_) => Ok(KafkaReplayPlan::response(ResponseKind::Heartbeat(
            HeartbeatResponse::default(),
        ))),
        RequestKind::LeaveGroup(_) => Ok(KafkaReplayPlan::response(ResponseKind::LeaveGroup(
            LeaveGroupResponse::default(),
        ))),
        RequestKind::OffsetCommit(request) => {
            Ok(KafkaReplayPlan::response(offset_commit_response(request)))
        }
        RequestKind::OffsetFetch(request) => {
            Ok(KafkaReplayPlan::response(offset_fetch_response(request)))
        }
        other => Err(anyhow!("unsupported Kafka request {other:?}")),
    }
}

fn api_versions_response() -> ResponseKind {
    ResponseKind::ApiVersions(
        ApiVersionsResponse::default().with_api_keys(
            REPLAY_API_VERSIONS
                .iter()
                .map(|version| {
                    ApiVersion::default()
                        .with_api_key(version.key as i16)
                        .with_min_version(version.min)
                        .with_max_version(version.max)
                })
                .collect(),
        ),
    )
}

fn metadata_response(
    request: &kafka_protocol::messages::MetadataRequest,
    target: &TargetKey,
    known_topics: BTreeSet<String>,
) -> ResponseKind {
    let requested = request.topics.as_ref().map_or(known_topics, |topics| {
        topics
            .iter()
            .filter_map(|topic| topic.name.as_ref().map(|name| name.0.to_string()))
            .collect()
    });
    let broker = MetadataResponseBroker::default()
        .with_node_id(KAFKA_NODE_ID.into())
        .with_host(StrBytes::from_string(target.host.clone()))
        .with_port(target.port.into());
    let topics = requested
        .into_iter()
        .map(|topic| {
            MetadataResponseTopic::default()
                .with_name(Some(topic_name(topic)))
                .with_partitions(vec![
                    MetadataResponsePartition::default()
                        .with_partition_index(0)
                        .with_leader_id(KAFKA_NODE_ID.into())
                        .with_replica_nodes(vec![KAFKA_NODE_ID.into()])
                        .with_isr_nodes(vec![KAFKA_NODE_ID.into()]),
                ])
        })
        .collect();
    ResponseKind::Metadata(
        MetadataResponse::default()
            .with_brokers(vec![broker])
            .with_controller_id(KAFKA_NODE_ID.into())
            .with_cluster_id(Some(StrBytes::from_static_str("replay-cluster")))
            .with_topics(topics),
    )
}

async fn produce_response(
    decoded: &DecodedKafkaRequest,
    target: &TargetKey,
    state: Arc<Mutex<ReplayState>>,
) -> Result<KafkaReplayPlan> {
    let records = records_from_produce(&decoded.request)?;
    let active_case_id = state.lock().await.active_case_id.clone();
    let RequestKind::Produce(request) = &decoded.request else {
        unreachable!();
    };
    let reservation = state.lock().await.kafka.reserve_produce(
        active_case_id.as_deref(),
        target,
        &records,
        request.acks == 0,
    );
    let Some(reservation) = reservation else {
        return Ok(KafkaReplayPlan::response(produce_result(request, 42)));
    };
    let timing = reservation.timing;
    if timing.outcome() != DependencyExchangeOutcome::Response {
        return Ok(KafkaReplayPlan::exchange(
            None,
            timing,
            KafkaReservation::Produce(reservation),
        ));
    }
    Ok(KafkaReplayPlan::exchange(
        Some(produce_result(request, 0)),
        timing,
        KafkaReservation::Produce(reservation),
    ))
}

fn produce_result(
    request: &kafka_protocol::messages::ProduceRequest,
    error_code: i16,
) -> ResponseKind {
    // INVALID_REQUEST is non-retriable for standard clients, so a semantic mismatch
    // fails the E2E promptly instead of entering the SDK retry loop.
    let responses = request
        .topic_data
        .iter()
        .map(|topic| {
            TopicProduceResponse::default()
                .with_name(topic.name.clone())
                .with_partition_responses(
                    topic
                        .partition_data
                        .iter()
                        .map(|partition| {
                            PartitionProduceResponse::default()
                                .with_index(partition.index)
                                .with_error_code(error_code)
                                .with_base_offset(0)
                        })
                        .collect(),
                )
        })
        .collect();
    ResponseKind::Produce(ProduceResponse::default().with_responses(responses))
}

async fn fetch_response(
    request: &kafka_protocol::messages::FetchRequest,
    target: &TargetKey,
    state: Arc<Mutex<ReplayState>>,
) -> Result<KafkaReplayPlan> {
    let requested_topics = request
        .topics
        .iter()
        .map(|topic| topic.topic.to_string())
        .collect::<BTreeSet<_>>();
    let active_case_id = state.lock().await.active_case_id.clone();
    let reservation = state.lock().await.kafka.reserve_fetch(
        active_case_id.as_deref(),
        target,
        &requested_topics,
    );
    let Some(reservation) = reservation else {
        return Ok(KafkaReplayPlan::response(build_fetch_response(
            request,
            Vec::new(),
        )?));
    };
    let timing = reservation.timing;
    if timing.outcome() == DependencyExchangeOutcome::ClientTerminated {
        return Ok(KafkaReplayPlan::exchange(
            None,
            timing,
            KafkaReservation::Fetch(reservation),
        ));
    }
    let response = build_fetch_response(request, reservation.records.clone())?;
    Ok(KafkaReplayPlan::exchange(
        Some(response),
        timing,
        KafkaReservation::Fetch(reservation),
    ))
}

fn build_fetch_response(
    request: &kafka_protocol::messages::FetchRequest,
    records: Vec<KafkaRecord>,
) -> Result<ResponseKind> {
    let mut by_topic = BTreeMap::<String, Vec<KafkaRecord>>::new();
    for record in records {
        by_topic
            .entry(record.topic.clone())
            .or_default()
            .push(record);
    }
    let responses = request
        .topics
        .iter()
        .map(|topic| {
            let topic_records = by_topic.remove(topic.topic.as_str()).unwrap_or_default();
            let high_watermark = topic_records.len() as i64;
            let encoded = encode_records(topic_records)?;
            let partitions = topic
                .partitions
                .iter()
                .map(|partition| {
                    let records =
                        (partition.partition == 0 && !encoded.is_empty()).then(|| encoded.clone());
                    Ok(PartitionData::default()
                        .with_partition_index(partition.partition)
                        .with_high_watermark(high_watermark)
                        .with_last_stable_offset(high_watermark)
                        .with_log_start_offset(0)
                        .with_records(records))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(FetchableTopicResponse::default()
                .with_topic(topic.topic.clone())
                .with_partitions(partitions))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ResponseKind::Fetch(
        FetchResponse::default().with_responses(responses),
    ))
}

fn encode_records(records: Vec<KafkaRecord>) -> Result<Bytes> {
    if records.is_empty() {
        return Ok(Bytes::new());
    }
    let records = records
        .into_iter()
        .enumerate()
        .map(|(offset, record)| Record {
            transactional: false,
            control: false,
            partition_leader_epoch: 0,
            producer_id: -1,
            producer_epoch: -1,
            timestamp_type: TimestampType::Creation,
            offset: offset as i64,
            sequence: -1,
            timestamp: record.timestamp_ms,
            key: record.key,
            value: record.value,
            headers: record
                .headers
                .into_iter()
                .map(|header| (StrBytes::from_string(header.name), header.value))
                .collect::<IndexMap<_, _>>(),
        })
        .collect::<Vec<_>>();
    let mut encoded = BytesMut::new();
    RecordBatchEncoder::encode(
        &mut encoded,
        &records,
        &RecordEncodeOptions {
            version: 2,
            compression: Compression::None,
        },
    )?;
    Ok(encoded.freeze())
}

fn list_offsets_response(request: &kafka_protocol::messages::ListOffsetsRequest) -> ResponseKind {
    let topics = request
        .topics
        .iter()
        .map(|topic| {
            ListOffsetsTopicResponse::default()
                .with_name(topic.name.clone())
                .with_partitions(
                    topic
                        .partitions
                        .iter()
                        .map(|partition| {
                            ListOffsetsPartitionResponse::default()
                                .with_partition_index(partition.partition_index)
                                .with_timestamp(0)
                                .with_offset(0)
                        })
                        .collect(),
                )
        })
        .collect();
    ResponseKind::ListOffsets(ListOffsetsResponse::default().with_topics(topics))
}

fn find_coordinator_response(
    request: &kafka_protocol::messages::FindCoordinatorRequest,
    target: &TargetKey,
    version: i16,
) -> ResponseKind {
    let response = if version >= 4 {
        FindCoordinatorResponse::default().with_coordinators(
            request
                .coordinator_keys
                .iter()
                .map(|key| {
                    Coordinator::default()
                        .with_key(key.clone())
                        .with_node_id(KAFKA_NODE_ID.into())
                        .with_host(StrBytes::from_string(target.host.clone()))
                        .with_port(target.port.into())
                })
                .collect(),
        )
    } else {
        FindCoordinatorResponse::default()
            .with_node_id(KAFKA_NODE_ID.into())
            .with_host(StrBytes::from_string(target.host.clone()))
            .with_port(target.port.into())
    };
    ResponseKind::FindCoordinator(response)
}

fn join_group_response(request: &kafka_protocol::messages::JoinGroupRequest) -> ResponseKind {
    let member_id = if request.member_id.is_empty() {
        StrBytes::from_static_str("replay-member")
    } else {
        request.member_id.clone()
    };
    let protocol = request.protocols.first();
    let response = JoinGroupResponse::default()
        .with_generation_id(1)
        .with_protocol_name(protocol.map(|protocol| protocol.name.clone()))
        .with_leader(member_id.clone())
        .with_member_id(member_id.clone())
        .with_members(
            protocol
                .map(|protocol| {
                    vec![
                        JoinGroupResponseMember::default()
                            .with_member_id(member_id)
                            .with_metadata(protocol.metadata.clone()),
                    ]
                })
                .unwrap_or_default(),
        );
    ResponseKind::JoinGroup(response)
}

fn sync_group_response(request: &kafka_protocol::messages::SyncGroupRequest) -> ResponseKind {
    let assignment = request
        .assignments
        .iter()
        .find(|assignment| assignment.member_id == request.member_id)
        .or_else(|| request.assignments.first())
        .map(|assignment| assignment.assignment.clone())
        .unwrap_or_default();
    ResponseKind::SyncGroup(SyncGroupResponse::default().with_assignment(assignment))
}

fn offset_commit_response(request: &kafka_protocol::messages::OffsetCommitRequest) -> ResponseKind {
    let topics = request
        .topics
        .iter()
        .map(|topic| {
            OffsetCommitResponseTopic::default()
                .with_name(topic.name.clone())
                .with_partitions(
                    topic
                        .partitions
                        .iter()
                        .map(|partition| {
                            OffsetCommitResponsePartition::default()
                                .with_partition_index(partition.partition_index)
                        })
                        .collect(),
                )
        })
        .collect();
    ResponseKind::OffsetCommit(OffsetCommitResponse::default().with_topics(topics))
}

fn offset_fetch_response(request: &kafka_protocol::messages::OffsetFetchRequest) -> ResponseKind {
    let topics = request
        .topics
        .as_ref()
        .into_iter()
        .flatten()
        .map(|topic| {
            OffsetFetchResponseTopic::default()
                .with_name(topic.name.clone())
                .with_partitions(
                    topic
                        .partition_indexes
                        .iter()
                        .map(|partition| {
                            OffsetFetchResponsePartition::default()
                                .with_partition_index(*partition)
                                .with_committed_offset(0)
                        })
                        .collect(),
                )
        })
        .collect();
    ResponseKind::OffsetFetch(OffsetFetchResponse::default().with_topics(topics))
}

fn topic_name(value: String) -> TopicName {
    TopicName(StrBytes::from_string(value))
}
