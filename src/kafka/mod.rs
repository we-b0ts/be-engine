mod profile;
mod recording;
mod records;
mod wire;

use bytes::Bytes;
pub(crate) use profile::{REPLAY_API_VERSIONS, replay_supports, replay_supports_api};
pub(crate) use recording::{KafkaConnectionContext, handle_connected};
pub(crate) use records::{records_from_fetch, records_from_produce};
pub(crate) use wire::{
    DecodedKafkaRequest, decode_request, decode_response, encode_response, read_frame,
    response_correlation_id, write_frame,
};

pub(crate) const KAFKA_NODE_ID: i32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KafkaRecord {
    pub(crate) topic: String,
    pub(crate) partition: i32,
    pub(crate) timestamp_ms: i64,
    pub(crate) key: Option<Bytes>,
    pub(crate) headers: Vec<KafkaHeader>,
    pub(crate) value: Option<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KafkaHeader {
    pub(crate) name: String,
    pub(crate) value: Option<Bytes>,
}
