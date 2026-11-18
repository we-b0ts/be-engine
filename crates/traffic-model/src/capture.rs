//! Bounded byte observations shared by recording and native semantic decoders.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BodyCapture {
    pub encoding: &'static str,
    pub original_len: usize,
    pub stored_len: usize,
    pub truncated: bool,
    pub data: String,
}

pub fn capture_body(bytes: &[u8], max_body_bytes: usize) -> BodyCapture {
    let stored_len = bytes.len().min(max_body_bytes);
    capture_body_with_original_len(&bytes[..stored_len], bytes.len())
}

pub fn capture_body_with_original_len(bytes: &[u8], original_len: usize) -> BodyCapture {
    BodyCapture {
        encoding: "base64",
        original_len,
        stored_len: bytes.len(),
        truncated: original_len > bytes.len(),
        data: STANDARD.encode(bytes),
    }
}

impl From<bytes::Bytes> for BodyCapture {
    fn from(value: bytes::Bytes) -> Self {
        capture_body(&value, value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_body_with_truncation() {
        let capture = capture_body(b"abcdef", 3);
        assert_eq!(capture.original_len, 6);
        assert_eq!(capture.stored_len, 3);
        assert!(capture.truncated);
        assert_eq!(capture.data, "YWJj");
    }
}
