use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use motan_codec::{
    Motan1RequestInspection, Motan1RequestLimits, inspect_motan1_request, inspect_request,
};
use motan_protocol::{
    DecodeStatus, Frame as ProtocolFrame, FrameInspection, Limits, MessageKind, ProtocolVersion,
    ResponseKind, decode_frame, inspect_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Traffic-e2e's recording adapter around the canonical Motan protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) raw: Bytes,
    pub(crate) request_id: u64,
    pub(crate) codec_version: u8,
    pub(crate) request: bool,
    protocol: ProtocolFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestIdentity {
    pub(crate) interface_name: Option<String>,
    pub(crate) method_name: Option<String>,
    pub(crate) parameter_desc: Option<String>,
    pub(crate) method_sign: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestMetadata {
    pub(crate) identity: RequestIdentity,
    pub(crate) group: Option<String>,
    pub(crate) heartbeat: bool,
}

impl RequestIdentity {
    pub(crate) fn command(&self) -> String {
        match (&self.interface_name, &self.method_name, &self.method_sign) {
            (Some(interface), Some(method), _) => format!("{interface}#{method}"),
            (_, _, Some(sign)) => format!("method-sign:{sign}"),
            _ => "unknown".to_string(),
        }
    }
}

pub(crate) async fn read_frame<R>(reader: &mut R, max_frame_bytes: usize) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let limits = limits(max_frame_bytes)?;
    let mut raw = vec![0_u8; 1];
    let read = reader
        .read(&mut raw)
        .await
        .context("failed to read Motan frame")?;
    if read == 0 {
        return Ok(None);
    }

    loop {
        match inspect_frame(&raw, limits)? {
            FrameInspection::Complete(_) => return decode_adapter(raw, limits).map(Some),
            FrameInspection::NeedMore { target } => {
                if target > max_frame_bytes {
                    bail!(
                        "Motan frame read target {target} exceeds configured limit {max_frame_bytes}"
                    );
                }
                let current = raw.len();
                if target <= current {
                    bail!("Motan frame parser returned a non-growing read target");
                }
                raw.resize(target, 0);
                reader
                    .read_exact(&mut raw[current..])
                    .await
                    .context("truncated Motan frame")?;
            }
        }
    }
}

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
    pub(crate) fn decode(raw: Vec<u8>) -> Result<Self> {
        decode_adapter(raw, Limits::default())
    }

    pub(crate) fn request_metadata(&self) -> Result<RequestMetadata> {
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

    pub(crate) fn motan1_request(&self) -> Result<Option<Motan1RequestInspection>> {
        (self.protocol.version == ProtocolVersion::Motan1)
            .then(|| inspect_motan1_request(&self.protocol, Motan1RequestLimits::default()))
            .transpose()
            .context("failed to decode Motan1 request arguments and attachments")
    }
}

pub(crate) fn response_status(frame: &Frame) -> &'static str {
    response_kind_label(frame.protocol.response_kind())
}

pub(crate) const fn response_kind_label(kind: Option<ResponseKind>) -> &'static str {
    match kind {
        Some(kind) => kind.as_str(),
        None => "unknown",
    }
}

pub(crate) const fn response_kind_status_code(kind: Option<ResponseKind>) -> u16 {
    match kind {
        Some(ResponseKind::Normal) => 200,
        Some(ResponseKind::Value) => 201,
        Some(ResponseKind::Void) => 204,
        Some(ResponseKind::Attachment) => 206,
        Some(ResponseKind::Exception) => 500,
        Some(ResponseKind::Other(_)) | None => 520,
    }
}

pub(crate) fn patch_request_id(raw: &mut [u8], request_id: u64) -> Result<()> {
    motan_protocol::patch_request_id(raw, request_id)
        .context("recorded Motan response has invalid framing")
}

fn limits(max_frame_bytes: usize) -> Result<Limits> {
    Limits {
        max_frame_bytes,
        max_metadata_bytes: max_frame_bytes,
        max_body_bytes: max_frame_bytes,
    }
    .validate()
    .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use motan_protocol::{
        FrameBuilder, META_GROUP, META_METHOD, META_METHOD_DESC, META_PATH, Metadata,
        ProtocolVersion, ResponseStatus,
    };

    use super::*;

    const MOTAN1_REQUEST: &[u8] = include_bytes!("../../tests/fixtures/motan/motan1-request.bin");

    #[tokio::test]
    async fn adapter_reads_java_motan1_and_shared_codec_decodes_identity() {
        let mut input = MOTAN1_REQUEST;
        let frame = read_frame(&mut input, Limits::default().max_frame_bytes)
            .await
            .unwrap()
            .unwrap();

        assert!(frame.request);
        assert_eq!(frame.codec_version, 1);
        let metadata = frame.request_metadata().unwrap();
        assert_eq!(metadata.group.as_deref(), Some("motan-rust-interop"));
        assert_eq!(
            metadata.identity.interface_name.as_deref(),
            Some("com.weibo.breeze.motan.EchoService")
        );
        assert_eq!(metadata.identity.method_name.as_deref(), Some("echo"));
    }

    #[tokio::test]
    async fn adapter_reads_direct_motan2_and_shared_codec_decodes_identity() {
        let mut metadata = Metadata::new();
        metadata.insert(META_GROUP, "group");
        metadata.insert(META_PATH, "example.UserService");
        metadata.insert(META_METHOD, "getUser");
        metadata.insert(META_METHOD_DESC, "long");
        let encoded = FrameBuilder::request(42)
            .serialization(7)
            .metadata(metadata)
            .encode()
            .unwrap();
        let mut input = encoded.as_ref();
        let frame = read_frame(&mut input, Limits::default().max_frame_bytes)
            .await
            .unwrap()
            .unwrap();

        assert!(frame.request);
        assert_eq!(frame.codec_version, 7);
        let metadata = frame.request_metadata().unwrap();
        assert_eq!(metadata.group.as_deref(), Some("group"));
        assert_eq!(metadata.identity.command(), "example.UserService#getUser");
    }

    #[test]
    fn response_status_uses_shared_version_specific_classification() {
        let motan2 = FrameBuilder::response(1)
            .status(ResponseStatus::Exception)
            .encode()
            .unwrap();
        let frame = decode_adapter(motan2.to_vec(), Limits::default()).unwrap();
        assert_eq!(frame.protocol.version, ProtocolVersion::Motan2);
        assert_eq!(response_status(&frame), "exception");
    }

    #[test]
    fn response_kind_status_mapping_preserves_motan1_value() {
        assert_eq!(response_kind_label(Some(ResponseKind::Value)), "value");
        assert_eq!(response_kind_status_code(Some(ResponseKind::Value)), 201);
        assert_eq!(response_kind_status_code(Some(ResponseKind::Normal)), 200);
        assert_eq!(response_kind_status_code(None), 520);
    }
}
