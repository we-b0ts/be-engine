use kafka_protocol::messages::offset_commit_response::{
    OffsetCommitResponse, OffsetCommitResponsePartition, OffsetCommitResponseTopic,
};
use kafka_protocol::messages::produce_response::{
    PartitionProduceResponse, ProduceResponse, TopicProduceResponse,
};
use kafka_protocol::messages::{ApiKey, RequestKind, ResponseKind};

use crate::access_policy::OperationClass;

const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
const GROUP_AUTHORIZATION_FAILED: i16 = 30;

pub(crate) fn classify_api(api_key: ApiKey) -> OperationClass {
    use ApiKey::*;

    if matches!(
        api_key,
        Fetch
            | ListOffsets
            | Metadata
            | OffsetFetch
            | DescribeGroups
            | ListGroups
            | ApiVersions
            | OffsetForLeaderEpoch
            | DescribeAcls
            | DescribeConfigs
            | DescribeLogDirs
            | DescribeDelegationToken
            | ListPartitionReassignments
            | DescribeClientQuotas
            | DescribeUserScramCredentials
            | DescribeQuorum
            | FetchSnapshot
            | DescribeCluster
            | DescribeProducers
            | DescribeTransactions
            | ListTransactions
            | ConsumerGroupDescribe
            | ListConfigResources
            | DescribeTopicPartitions
            | ShareGroupDescribe
            | ShareFetch
            | ReadShareGroupState
            | ReadShareGroupStateSummary
            | DescribeShareGroupOffsets
    ) {
        OperationClass::Read
    } else if matches!(
        api_key,
        FindCoordinator
            | JoinGroup
            | Heartbeat
            | LeaveGroup
            | SyncGroup
            | SaslHandshake
            | SaslAuthenticate
            | ConsumerGroupHeartbeat
            | ShareGroupHeartbeat
    ) {
        OperationClass::Session
    } else if matches!(
        api_key,
        Produce
            | OffsetCommit
            | CreateTopics
            | DeleteTopics
            | DeleteRecords
            | InitProducerId
            | AddPartitionsToTxn
            | AddOffsetsToTxn
            | EndTxn
            | WriteTxnMarkers
            | TxnOffsetCommit
            | CreateAcls
            | DeleteAcls
            | AlterConfigs
            | AlterReplicaLogDirs
            | CreatePartitions
            | CreateDelegationToken
            | RenewDelegationToken
            | ExpireDelegationToken
            | DeleteGroups
            | ElectLeaders
            | IncrementalAlterConfigs
            | AlterPartitionReassignments
            | OffsetDelete
            | AlterClientQuotas
            | AlterUserScramCredentials
            | Vote
            | BeginQuorumEpoch
            | EndQuorumEpoch
            | AlterPartition
            | UpdateFeatures
            | Envelope
            | AllocateProducerIds
            | BrokerRegistration
            | BrokerHeartbeat
            | UnregisterBroker
            | ControllerRegistration
            | PushTelemetry
            | AssignReplicasToDirs
            | ShareAcknowledge
            | AddRaftVoter
            | RemoveRaftVoter
            | UpdateRaftVoter
            | InitializeShareGroupState
            | WriteShareGroupState
            | DeleteShareGroupState
            | AlterShareGroupOffsets
            | DeleteShareGroupOffsets
    ) {
        OperationClass::Write
    } else {
        OperationClass::Unknown
    }
}

pub(crate) fn rejection_response(request: &RequestKind) -> Option<ResponseKind> {
    match request {
        RequestKind::Produce(request) if request.acks != 0 => {
            let responses = request
                .topic_data
                .iter()
                .map(|topic| {
                    TopicProduceResponse::default()
                        .with_name(topic.name.clone())
                        .with_topic_id(topic.topic_id)
                        .with_partition_responses(
                            topic
                                .partition_data
                                .iter()
                                .map(|partition| {
                                    PartitionProduceResponse::default()
                                        .with_index(partition.index)
                                        .with_error_code(TOPIC_AUTHORIZATION_FAILED)
                                        .with_base_offset(-1)
                                        .with_log_append_time_ms(-1)
                                        .with_log_start_offset(-1)
                                })
                                .collect(),
                        )
                })
                .collect();
            Some(ResponseKind::Produce(
                ProduceResponse::default().with_responses(responses),
            ))
        }
        RequestKind::Produce(_) => None,
        RequestKind::OffsetCommit(request) => {
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
                                        .with_error_code(GROUP_AUTHORIZATION_FAILED)
                                })
                                .collect(),
                        )
                })
                .collect();
            Some(ResponseKind::OffsetCommit(
                OffsetCommitResponse::default().with_topics(topics),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use kafka_protocol::messages::offset_commit_request::{
        OffsetCommitRequest, OffsetCommitRequestPartition, OffsetCommitRequestTopic,
    };
    use kafka_protocol::messages::produce_request::{
        PartitionProduceData, ProduceRequest, TopicProduceData,
    };
    use kafka_protocol::protocol::StrBytes;

    use super::*;

    #[test]
    fn classifies_reads_sessions_writes_and_unknowns() {
        assert_eq!(classify_api(ApiKey::Fetch), OperationClass::Read);
        assert_eq!(classify_api(ApiKey::JoinGroup), OperationClass::Session);
        assert_eq!(classify_api(ApiKey::Produce), OperationClass::Write);
        assert_eq!(
            classify_api(ApiKey::GetTelemetrySubscriptions),
            OperationClass::Unknown
        );
    }

    #[test]
    fn builds_native_rejections_for_produce_and_offset_commit() {
        let produce =
            RequestKind::Produce(ProduceRequest::default().with_acks(1).with_topic_data(vec![
                TopicProduceData::default()
                    .with_name(StrBytes::from_static_str("events").into())
                    .with_partition_data(vec![PartitionProduceData::default().with_index(3)]),
            ]));
        let Some(ResponseKind::Produce(response)) = rejection_response(&produce) else {
            panic!("expected Produce rejection");
        };
        assert_eq!(response.responses[0].partition_responses[0].error_code, 29);

        let commit = RequestKind::OffsetCommit(OffsetCommitRequest::default().with_topics(vec![
            OffsetCommitRequestTopic::default()
                .with_name(StrBytes::from_static_str("events").into())
                .with_partitions(vec![
                    OffsetCommitRequestPartition::default().with_partition_index(3),
                ]),
        ]));
        let Some(ResponseKind::OffsetCommit(response)) = rejection_response(&commit) else {
            panic!("expected OffsetCommit rejection");
        };
        assert_eq!(response.topics[0].partitions[0].error_code, 30);
    }
}
