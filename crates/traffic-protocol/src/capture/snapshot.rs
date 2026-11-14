//! Immutable native payload and capture facts crossing the host boundary.
use anyhow::Result;
use serde::{Serialize, Serializer};
use serde_json::Value;

use super::{CaptureEvidence, CaptureFacts};

#[derive(Clone)]
pub struct CaptureSnapshot {
    kind: &'static str,
    payload: Value,
    facts: CaptureFacts,
}

impl CaptureSnapshot {
    pub fn capture(event: &impl CaptureEvidence) -> Result<Self> {
        let payload = super::payload(event)?;
        if let Some(outcome) = payload.get("outcome") {
            let outcome = serde_json::from_value::<traffic_model::DependencyExchangeOutcome>(
                outcome.clone(),
            )?;
            outcome.validate()?;
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

impl CaptureEvidence for CaptureSnapshot {
    fn event_type(&self) -> &'static str {
        self.kind
    }
    fn capture_facts(&self) -> CaptureFacts {
        self.facts.clone()
    }
}

impl Serialize for CaptureSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.payload.serialize(serializer)
    }
}

impl std::fmt::Debug for CaptureSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureSnapshot")
            .field("kind", &self.kind)
            .finish()
    }
}
