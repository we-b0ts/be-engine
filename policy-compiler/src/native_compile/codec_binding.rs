//! Typed binding compatibility for persisted native response selectors.
use crate::Codec;

pub fn protobuf_schema(codec: &Codec) -> Option<traffic_codec_protobuf::ProtobufCodec> {
    if codec.id() != "protobuf" {
        return None;
    }
    serde_json::from_value(codec.configuration().clone()).ok()
}
