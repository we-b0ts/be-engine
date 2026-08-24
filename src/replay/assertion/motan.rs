use anyhow::{Context, Result, bail, ensure};
use motan_breeze::{Limits as BreezeLimits, SERIALIZATION_ID as BREEZE_SERIALIZATION_ID};
use motan_protocol::{
    DecodeStatus, Limits, META_PROCESS_TIME, MessageKind, ProtocolVersion, decode_frame,
};
use motan_simple::{Limits as SimpleLimits, SERIALIZATION_ID as SIMPLE_SERIALIZATION_ID};

const MOTAN2_PROXY_FLAG: u8 = 0x02;
const BREEZE_BYTE_ARRAY: u8 = 0x9d;
const SIMPLE_STRING: u8 = 0x01;
const SIMPLE_BYTE_ARRAY: u8 = 0x03;
const MOTAN1_OUTER_LENGTH_OFFSET: usize = 12;
const MOTAN1_INNER_LENGTH_OFFSET: usize = 28;
const LENGTH_FIELD_BYTES: usize = 4;

pub(super) struct ComparableResponseFrame {
    encoded: Vec<u8>,
    body_offset: usize,
    body_kind: ComparableBodyKind,
    carrier: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ComparableBodyKind {
    WireBytes,
    BreezeString,
    BreezeByteArray,
    BreezeValue,
    SimpleString,
    SimpleByteArray,
    SimpleValue,
}

impl ComparableBodyKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::WireBytes => "wire_bytes",
            Self::BreezeString => "breeze_string",
            Self::BreezeByteArray => "breeze_byte_array",
            Self::BreezeValue => "breeze_value",
            Self::SimpleString => "simple_string",
            Self::SimpleByteArray => "simple_byte_array",
            Self::SimpleValue => "simple_value",
        }
    }
}

impl ComparableResponseFrame {
    pub(super) fn body(&self) -> &[u8] {
        &self.encoded[self.body_offset..]
    }

    pub(super) fn carrier(&self) -> &[u8] {
        &self.carrier
    }

    pub(super) const fn body_kind(&self) -> ComparableBodyKind {
        self.body_kind
    }
}

pub(super) fn comparable_response_frame(
    raw: &[u8],
    label: &str,
) -> Result<ComparableResponseFrame> {
    let capacity = raw.len().max(32);
    let limits = Limits {
        max_frame_bytes: capacity,
        max_metadata_bytes: capacity,
        max_body_bytes: capacity,
    };
    let DecodeStatus::Complete(mut frame) = decode_frame(raw, limits)
        .with_context(|| format!("{label} contains an invalid Motan response frame"))?
    else {
        bail!("{label} contains an incomplete Motan response frame");
    };
    ensure!(
        frame.raw().len() == raw.len(),
        "{label} contains trailing bytes after its Motan response frame"
    );
    ensure!(
        matches!(
            frame.version,
            ProtocolVersion::Motan1 | ProtocolVersion::Motan2
        ) && frame.kind == MessageKind::Response,
        "{label} does not contain a Motan response frame"
    );

    while frame.metadata.remove(META_PROCESS_TIME).is_some() {}
    let version = frame.version;
    let serialization = frame.serialization;
    let body_len = frame.body.len();
    let (business_payload_offset, body_kind) = business_body(version, serialization, &frame.body);
    let mut encoded = frame
        .encode()
        .map(|encoded| encoded.to_vec())
        .with_context(|| format!("failed to normalize {label} Motan response frame"))?;
    if frame.version == ProtocolVersion::Motan2 {
        // PROXY describes how a request reached the service. The observed Java
        // source may clear it on the response while another compatible server
        // reflects it, so it is not response-semantic evidence.
        encoded[2] &= !MOTAN2_PROXY_FLAG;
    }
    let body_offset = encoded
        .len()
        .checked_sub(body_len)
        .context("normalized Motan response body exceeds its frame")?;
    ensure!(
        encoded[body_offset..] == frame.body,
        "normalized {label} Motan response body is not at the end of its frame"
    );
    let mut carrier = encoded[..body_offset].to_vec();
    clear_derived_body_lengths(version, &mut carrier)?;
    Ok(ComparableResponseFrame {
        encoded,
        body_offset: body_offset + business_payload_offset,
        body_kind,
        carrier,
    })
}

fn business_body(
    version: ProtocolVersion,
    serialization: Option<u8>,
    body: &[u8],
) -> (usize, ComparableBodyKind) {
    if version != ProtocolVersion::Motan2 {
        return (0, ComparableBodyKind::WireBytes);
    }

    match serialization {
        Some(BREEZE_SERIALIZATION_ID) => breeze_business_body(body),
        Some(SIMPLE_SERIALIZATION_ID) => simple_business_body(body),
        _ => (0, ComparableBodyKind::WireBytes),
    }
}

fn breeze_business_body(body: &[u8]) -> (usize, ComparableBodyKind) {
    let limits = BreezeLimits {
        max_input_bytes: body.len(),
        max_output_bytes: body.len(),
        max_string_bytes: body.len(),
    };
    if let Ok(value) = motan_breeze::from_slice::<&str>(body, limits) {
        return (body.len() - value.len(), ComparableBodyKind::BreezeString);
    }
    breeze_byte_array(body).map_or((0, ComparableBodyKind::BreezeValue), |payload| {
        (
            body.len() - payload.len(),
            ComparableBodyKind::BreezeByteArray,
        )
    })
}

fn simple_business_body(body: &[u8]) -> (usize, ComparableBodyKind) {
    let limits = SimpleLimits {
        max_input_bytes: body.len(),
        max_output_bytes: body.len(),
        max_string_bytes: body.len(),
        max_binary_bytes: body.len(),
        ..SimpleLimits::default()
    };
    match body.first().copied() {
        Some(SIMPLE_STRING) => motan_simple::from_slice::<&str>(body, limits)
            .map_or((0, ComparableBodyKind::SimpleValue), |payload| {
                (body.len() - payload.len(), ComparableBodyKind::SimpleString)
            }),
        Some(SIMPLE_BYTE_ARRAY) => motan_simple::from_slice::<&[u8]>(body, limits).map_or(
            (0, ComparableBodyKind::SimpleValue),
            |payload| {
                (
                    body.len() - payload.len(),
                    ComparableBodyKind::SimpleByteArray,
                )
            },
        ),
        _ => (0, ComparableBodyKind::SimpleValue),
    }
}

fn breeze_byte_array(body: &[u8]) -> Option<&[u8]> {
    let (&tag, encoded) = body.split_first()?;
    if tag != BREEZE_BYTE_ARRAY || encoded.len() < LENGTH_FIELD_BYTES {
        return None;
    }
    let (length, payload) = encoded.split_at(LENGTH_FIELD_BYTES);
    let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    (payload.len() == length).then_some(payload)
}

fn clear_derived_body_lengths(version: ProtocolVersion, carrier: &mut [u8]) -> Result<()> {
    match version {
        ProtocolVersion::Motan1 => {
            for offset in [MOTAN1_OUTER_LENGTH_OFFSET, MOTAN1_INNER_LENGTH_OFFSET] {
                let field = carrier
                    .get_mut(offset..offset + LENGTH_FIELD_BYTES)
                    .context("normalized Motan1 response has no complete body-length field")?;
                field.fill(0);
            }
        }
        ProtocolVersion::Motan2 => {
            let offset = carrier
                .len()
                .checked_sub(LENGTH_FIELD_BYTES)
                .context("normalized Motan2 response has no body-length field")?;
            carrier[offset..].fill(0);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use motan_json::Json;
    use motan_protocol::FrameBuilder;
    use serde::Serialize;

    use super::*;

    fn comparable_simple_response(body: Vec<u8>) -> ComparableResponseFrame {
        let encoded = FrameBuilder::response(42)
            .serialization(SIMPLE_SERIALIZATION_ID)
            .body(body)
            .encode()
            .unwrap();
        comparable_response_frame(&encoded, "response").unwrap()
    }

    #[test]
    fn motan2_response_proxy_flag_does_not_affect_comparison() {
        let source = FrameBuilder::response(42)
            .body("response")
            .encode()
            .unwrap();
        let target = FrameBuilder::response(42)
            .proxy(true)
            .body("response")
            .encode()
            .unwrap();

        let source = comparable_response_frame(&source, "source response").unwrap();
        let target = comparable_response_frame(&target, "target response").unwrap();

        assert_eq!(source.encoded, target.encoded);
        assert_eq!(source.carrier(), target.carrier());
        assert_eq!(source.body(), target.body());
    }

    #[test]
    fn motan2_body_length_does_not_affect_carrier_comparison() {
        let source = FrameBuilder::response(42).body("short").encode().unwrap();
        let target = FrameBuilder::response(42)
            .body("a longer response")
            .encode()
            .unwrap();

        let source = comparable_response_frame(&source, "source response").unwrap();
        let target = comparable_response_frame(&target, "target response").unwrap();

        assert_eq!(source.carrier(), target.carrier());
        assert_ne!(source.body(), target.body());
    }

    #[test]
    fn motan2_breeze_non_payload_value_keeps_its_wire_body() {
        let encoded = FrameBuilder::response(42)
            .serialization(BREEZE_SERIALIZATION_ID)
            .body(vec![0x51])
            .encode()
            .unwrap();

        let frame = comparable_response_frame(&encoded, "response").unwrap();

        assert_eq!(frame.body(), &[0x51]);
        assert_eq!(frame.body_kind(), ComparableBodyKind::BreezeValue);
    }

    #[test]
    fn motan2_simple_json_request_and_response_wrappers_expose_business_json() {
        #[derive(Serialize)]
        struct Request {
            query: &'static str,
        }

        #[derive(Serialize)]
        struct Response {
            found: bool,
        }

        let request = motan_simple::to_vec(
            &Json::new(Request { query: "motan" }),
            SimpleLimits::default(),
        )
        .unwrap();
        let response = motan_simple::to_vec(
            &Json::new(Response { found: true }),
            SimpleLimits::default(),
        )
        .unwrap();

        let request = comparable_simple_response(request);
        let response = comparable_simple_response(response);

        assert_eq!(request.body(), br#"{"query":"motan"}"#);
        assert_eq!(response.body(), br#"{"found":true}"#);
        assert_eq!(request.body_kind(), ComparableBodyKind::SimpleString);
        assert_eq!(response.body_kind(), ComparableBodyKind::SimpleString);
    }

    #[test]
    fn motan2_simple_byte_array_exposes_its_business_payload() {
        let body =
            motan_simple::to_vec(br#"{"found":true}"#.as_slice(), SimpleLimits::default()).unwrap();

        let frame = comparable_simple_response(body);

        assert_eq!(frame.body(), br#"{"found":true}"#);
        assert_eq!(frame.body_kind(), ComparableBodyKind::SimpleByteArray);
    }

    #[test]
    fn motan2_simple_string_and_byte_array_remain_distinct() {
        let text = motan_simple::to_vec(r#"{"found":true}"#, SimpleLimits::default()).unwrap();
        let bytes =
            motan_simple::to_vec(br#"{"found":true}"#.as_slice(), SimpleLimits::default()).unwrap();

        let text = comparable_simple_response(text);
        let bytes = comparable_simple_response(bytes);

        assert_eq!(text.body(), bytes.body());
        assert_eq!(text.body_kind(), ComparableBodyKind::SimpleString);
        assert_eq!(bytes.body_kind(), ComparableBodyKind::SimpleByteArray);
    }

    #[test]
    fn motan2_malformed_simple_payload_keeps_its_wire_body() {
        let body = vec![SIMPLE_STRING, 0, 0, 0, 3, b'{'];

        let frame = comparable_simple_response(body.clone());

        assert_eq!(frame.body(), body);
        assert_eq!(frame.body_kind(), ComparableBodyKind::SimpleValue);
    }

    #[test]
    fn motan2_simple_non_payload_value_keeps_its_wire_body() {
        let body = motan_simple::to_vec(&42_i32, SimpleLimits::default()).unwrap();

        let frame = comparable_simple_response(body.clone());

        assert_eq!(frame.body(), body);
        assert_eq!(frame.body_kind(), ComparableBodyKind::SimpleValue);
    }
}
