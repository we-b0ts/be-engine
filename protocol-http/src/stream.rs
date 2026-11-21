//! Byte-range timing evidence for an HTTP dependency response stream.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStream {
    pub version: u8,
    pub headers_ms: u64,
    pub chunks: Vec<ResponseChunk>,
    pub end_ms: u64,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trailers: Option<std::collections::BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseChunk {
    pub at_ms: u64,
    pub start: usize,
    pub end: usize,
}

impl ResponseStream {
    pub fn validate(&self, payload_len: usize) -> Result<()> {
        ensure!(
            self.complete,
            "HTTP dependency stream capture is incomplete"
        );
        self.validate_prefix(payload_len)
    }

    /// Validate the fully captured, flushed prefix retained at Source stop.
    /// This does not certify a business response EOF.
    pub fn validate_prefix(&self, payload_len: usize) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2),
            "unsupported HTTP stream evidence version"
        );
        let mut offset = 0;
        let mut at_ms = self.headers_ms;
        for chunk in &self.chunks {
            ensure!(
                chunk.start == offset && chunk.end > chunk.start && chunk.end <= payload_len,
                "HTTP stream chunks do not cover the recorded payload contiguously"
            );
            ensure!(
                chunk.at_ms >= at_ms,
                "HTTP stream chunk timing is not monotonic"
            );
            offset = chunk.end;
            at_ms = chunk.at_ms;
        }
        ensure!(
            offset == payload_len,
            "HTTP stream metadata does not cover the whole response payload"
        );
        ensure!(
            self.end_ms >= at_ms && self.end_ms <= 86_400_000,
            "HTTP stream end timing is invalid"
        );
        Ok(())
    }
}
