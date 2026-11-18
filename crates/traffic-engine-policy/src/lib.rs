//! Installed policy authoring, compilation and immutable signing-key contracts.
pub mod formats;
pub mod policy;
pub mod signing;
pub mod time_copies;

#[cfg(test)]
use traffic_engine_config::{AppConfig, config, recording_api::RecordingApi};
#[cfg(test)]
use traffic_engine_evidence::policy_evidence;
#[cfg(test)]
mod value_codec {
    pub fn protobuf(schema: traffic_codec_protobuf::ProtobufCodec) -> crate::policy::Codec {
        crate::policy::Codec::registered("protobuf", serde_json::to_value(schema).unwrap()).unwrap()
    }
}
