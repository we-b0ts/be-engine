use kafka_protocol::messages::ApiKey;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KafkaApiVersion {
    pub(crate) key: ApiKey,
    pub(crate) min: i16,
    pub(crate) max: i16,
}

pub(crate) const REPLAY_API_VERSIONS: &[KafkaApiVersion] = &[
    KafkaApiVersion {
        key: ApiKey::Produce,
        min: 3,
        max: 8,
    },
    KafkaApiVersion {
        key: ApiKey::Fetch,
        min: 4,
        max: 11,
    },
    KafkaApiVersion {
        key: ApiKey::ListOffsets,
        min: 1,
        max: 5,
    },
    KafkaApiVersion {
        key: ApiKey::Metadata,
        min: 0,
        max: 8,
    },
    KafkaApiVersion {
        key: ApiKey::OffsetCommit,
        min: 2,
        max: 7,
    },
    KafkaApiVersion {
        key: ApiKey::OffsetFetch,
        min: 1,
        max: 5,
    },
    KafkaApiVersion {
        key: ApiKey::FindCoordinator,
        min: 0,
        max: 2,
    },
    KafkaApiVersion {
        key: ApiKey::JoinGroup,
        min: 0,
        max: 5,
    },
    KafkaApiVersion {
        key: ApiKey::Heartbeat,
        min: 0,
        max: 3,
    },
    KafkaApiVersion {
        key: ApiKey::LeaveGroup,
        min: 0,
        max: 3,
    },
    KafkaApiVersion {
        key: ApiKey::SyncGroup,
        min: 0,
        max: 3,
    },
    KafkaApiVersion {
        key: ApiKey::ApiVersions,
        min: 0,
        max: 3,
    },
];

pub(crate) fn replay_supports(key: ApiKey, version: i16) -> bool {
    REPLAY_API_VERSIONS
        .iter()
        .any(|candidate| candidate.key == key && (candidate.min..=candidate.max).contains(&version))
}

pub(crate) fn replay_supports_api(key: ApiKey) -> bool {
    REPLAY_API_VERSIONS
        .iter()
        .any(|candidate| candidate.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_excludes_flexible_and_transactional_apis() {
        assert!(replay_supports(ApiKey::Produce, 8));
        assert!(!replay_supports(ApiKey::Produce, 9));
        assert!(!replay_supports(ApiKey::InitProducerId, 0));
        assert!(!replay_supports(ApiKey::EndTxn, 0));
    }
}
