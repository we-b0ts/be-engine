//! Shared content strategies plus the primary SSE carrier adapter.
pub(crate) mod sse;
#[cfg(test)]
pub(crate) use traffic_contract::codec::CodecKind;
pub(crate) use traffic_contract::codec::{CodecPlan, DecodedValue};
#[cfg(test)]
use traffic_contract::codec::{Presence, ValueCodec};
#[cfg(test)]
pub(crate) use traffic_contract::codec::{measured_compiles, measured_decodes};
#[cfg(test)]
mod tests;

pub(crate) fn compile(codec: &crate::policy::Codec) -> anyhow::Result<CodecPlan> {
    CodecPlan::compile(codec, traffic_extensions::codecs())
}

pub(crate) fn try_recognize(
    source: &[u8],
    metadata: &traffic_value::Value,
) -> anyhow::Result<Option<CodecPlan>> {
    CodecPlan::try_recognize(source, metadata, traffic_extensions::codecs())
}

#[cfg(test)]
pub(crate) fn protobuf(schema: traffic_codec_protobuf::ProtobufCodec) -> crate::policy::Codec {
    crate::policy::Codec::registered(
        "protobuf",
        serde_json::to_value(schema).expect("typed codec schema is serializable"),
    )
    .expect("typed codec options form a named configuration")
}

pub(crate) fn protobuf_schema(
    codec: &crate::policy::Codec,
) -> Option<traffic_codec_protobuf::ProtobufCodec> {
    traffic_policy_compiler::native_compile::codec_binding::protobuf_schema(codec)
}

pub(crate) struct CodecView;

impl CodecView {
    pub(crate) fn decode(
        codec: &crate::policy::Codec,
        bytes: &[u8],
    ) -> anyhow::Result<DecodedValue> {
        compile(codec)?.decode(bytes)
    }
}
