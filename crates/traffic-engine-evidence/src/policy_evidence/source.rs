//! Authenticated references into immutable semantic recordings. Native owners
//! reconstruct their exact envelopes; this layer never normalizes their values.
use super::*;
use crate::policy::Protocol;
use serde_json::Value;

pub use traffic_recording_store::source::SourceRecord;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SourcePayload {
    pub record: SourceRecord,
    pub protocol: Protocol,
    pub surface: Surface,
}

impl SourcePayload {
    pub(super) fn read(&self, context: &Path) -> Result<Vec<u8>> {
        let bytes = self.record.read()?;
        let event: Value = serde_json::from_slice(&bytes)?;
        let protocol = serde_json::to_value(self.protocol)?;
        crate::protocols::default_providers()
            .evidence()
            .source_payload(
                protocol
                    .as_str()
                    .context("Source protocol identity is invalid")?,
                &event,
                self.surface.dependency_side()?,
                &crate::request_headers::SourceSecrets::new(context),
            )?
            .context("Source protocol has no registered payload projection")
    }
}

pub(super) fn identity(metadata: &SourceIdentity, protocol: Protocol) -> Result<String> {
    Ok(serde_json::to_string(&(metadata, protocol))?)
}
