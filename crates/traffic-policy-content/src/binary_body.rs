const SIMPLE_BYTE_ARRAY: u8 = 3;
const SIMPLE_BYTE_ARRAY_HEADER: usize = 5;

/// Envelope carrying one binary business value inside a normalized response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEnvelope {
    /// Simple `byte[]` serialization: tag, big-endian length, payload.
    SimpleByteArray,
    /// The serialized business value occupies the whole response body.
    Raw,
}

impl BodyEnvelope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SimpleByteArray => "simple_byte_array",
            Self::Raw => "raw",
        }
    }
}

/// Returns the payload of a simple byte-array envelope when the body has
/// that exact framing.
pub fn simple_payload(body: &[u8]) -> Option<&[u8]> {
    if body.len() < SIMPLE_BYTE_ARRAY_HEADER || body[0] != SIMPLE_BYTE_ARRAY {
        return None;
    }
    let declared = u32::from_be_bytes(body[1..5].try_into().expect("four-byte length")) as usize;
    if declared != body.len() - SIMPLE_BYTE_ARRAY_HEADER {
        return None;
    }
    Some(&body[SIMPLE_BYTE_ARRAY_HEADER..])
}
