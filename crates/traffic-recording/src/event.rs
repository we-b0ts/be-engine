//! A native capture snapshot queued and persisted through the shared writer.
use anyhow::Result;
use serde::{Serialize, Serializer};
use serde_json::Value;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts};

#[derive(Clone)]
pub struct CapturedEvent {
    kind: &'static str,
    payload: Value,
    facts: CaptureFacts,
}

impl CapturedEvent {
    pub fn capture(event: &impl CaptureEvidence) -> Result<Self> {
        let payload = traffic_protocol::capture::payload(event)?;
        if let Some(outcome) = payload.get("outcome") {
            serde_json::from_value::<traffic_model::DependencyExchangeOutcome>(outcome.clone())?;
        }
        Ok(Self {
            kind: event.event_type(),
            payload,
            facts: event.capture_facts(),
        })
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn payload(&self) -> &Value {
        &self.payload
    }
    pub fn facts(&self) -> &CaptureFacts {
        &self.facts
    }
}

impl CaptureEvidence for CapturedEvent {
    fn event_type(&self) -> &'static str {
        self.kind
    }
    fn capture_facts(&self) -> CaptureFacts {
        self.facts.clone()
    }
}

impl Serialize for CapturedEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.payload.serialize(serializer)
    }
}

impl std::fmt::Debug for CapturedEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapturedEvent")
            .field("kind", &self.kind)
            .finish()
    }
}
