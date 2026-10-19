//! Byte-range timing evidence for a bounded HTTP dependency response stream.

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
    pub(crate) fn validate(&self, payload_len: usize) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported HTTP stream evidence version"
        );
        ensure!(
            self.complete,
            "HTTP dependency stream was not captured through EOF"
        );
        ensure!(
            self.chunks.len() <= 10_000,
            "HTTP stream exceeds chunk evidence limit"
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
