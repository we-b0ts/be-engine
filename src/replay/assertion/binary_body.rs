use anyhow::{Context, Result, ensure};

const SIMPLE_BYTE_ARRAY: u8 = 3;
const SIMPLE_BYTE_ARRAY_HEADER: usize = 5;

/// Framing that carries a binary business value inside a Motan response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MotanBodyEnvelope {
    /// Motan simple serialization `byte[]`: tag, big-endian length, payload.
    SimpleByteArray,
    /// The serialized business value occupies the whole Motan body.
    Raw,
}

impl MotanBodyEnvelope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SimpleByteArray => "simple_byte_array",
            Self::Raw => "raw",
        }
    }
}

pub(super) fn extract_simple_payload(body: &[u8]) -> Result<&[u8]> {
    ensure!(
        body.len() >= SIMPLE_BYTE_ARRAY_HEADER && body[0] == SIMPLE_BYTE_ARRAY,
        "Motan body is not a simple byte-array envelope"
    );
    simple_payload(body).context("Motan simple byte-array length does not match its payload")
}

/// Returns the payload of a Motan simple byte-array envelope when the body has
/// that exact framing.
pub(super) fn simple_payload(body: &[u8]) -> Option<&[u8]> {
    if body.len() < SIMPLE_BYTE_ARRAY_HEADER || body[0] != SIMPLE_BYTE_ARRAY {
        return None;
    }
    let declared = u32::from_be_bytes(body[1..5].try_into().expect("four-byte length")) as usize;
    if declared != body.len() - SIMPLE_BYTE_ARRAY_HEADER {
        return None;
    }
    Some(&body[SIMPLE_BYTE_ARRAY_HEADER..])
}
