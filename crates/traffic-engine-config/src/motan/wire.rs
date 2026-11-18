use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use motan_codec::inspect_request;
use motan_protocol::{
    DecodeStatus, Frame as ProtocolFrame, Limits, MessageKind, ResponseKind, decode_frame,
};

/// Traffic-e2e's recording adapter around the canonical Motan protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub raw: Bytes,
    pub request_id: u64,
    pub codec_version: u8,
    pub request: bool,
    protocol: ProtocolFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdentity {
    pub interface_name: Option<String>,
    pub method_name: Option<String>,
    pub parameter_desc: Option<String>,
    pub method_sign: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMetadata {
    pub identity: RequestIdentity,
    pub group: Option<String>,
    pub heartbeat: bool,
}

impl RequestIdentity {}

fn decode_adapter(raw: Vec<u8>, limits: Limits) -> Result<Frame> {
    let DecodeStatus::Complete(protocol) = decode_frame(&raw, limits)? else {
        return Err(anyhow!(
            "complete Motan frame became incomplete during decoding"
        ));
    };
    let raw = protocol.raw().clone();
    Ok(Frame {
        request_id: protocol.request_id,
        codec_version: protocol.codec(),
        request: protocol.kind == MessageKind::Request,
        raw,
        protocol,
    })
}

impl Frame {
    pub fn decode(raw: Vec<u8>) -> Result<Self> {
        decode_adapter(raw, Limits::default())
    }

    pub fn request_metadata(&self) -> Result<RequestMetadata> {
        let envelope =
            inspect_request(&self.protocol).context("failed to decode Motan request envelope")?;
        Ok(RequestMetadata {
            group: envelope.group,
            heartbeat: envelope.heartbeat,
            identity: RequestIdentity {
                interface_name: envelope.interface_name,
                method_name: envelope.method_name,
                parameter_desc: envelope.parameter_desc,
                method_sign: envelope.method_sign,
            },
        })
    }
}

pub const fn response_kind_status_code(kind: Option<ResponseKind>) -> u16 {
    match kind {
        Some(ResponseKind::Normal) => 200,
        Some(ResponseKind::Value) => 201,
        Some(ResponseKind::Void) => 204,
        Some(ResponseKind::Attachment) => 206,
        Some(ResponseKind::Exception) => 500,
        Some(ResponseKind::Other(_)) | None => 520,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn response_kind_status_mapping_preserves_motan1_value() {
        assert_eq!(response_kind_status_code(Some(ResponseKind::Value)), 201);
        assert_eq!(response_kind_status_code(Some(ResponseKind::Normal)), 200);
        assert_eq!(response_kind_status_code(None), 520);
    }
}
