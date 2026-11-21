//! Immutable native payload and capture facts crossing the host boundary.
use anyhow::{Result, ensure};
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
        let facts = event.capture_facts();
        facts.outcome.validate()?;
        let payload = super::native_payload(event)?;
        if let Some(outcome) = payload.get("outcome") {
            ensure!(
                *outcome == serde_json::to_value(facts.outcome)?,
                "native payload conflicts with the framework outcome"
            );
        }
        Ok(Self {
            kind: event.event_type(),
            payload,
            facts,
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

    pub fn with_source_predecessor(mut self, dependency: Option<u64>) -> Self {
        if let Some(dependency) = dependency {
            self.payload["source_after_id"] = Value::from(dependency);
        }
        self
    }

    pub fn with_recording_identity(mut self, dependency_id: uuid::Uuid) -> Result<Self> {
        if !self
            .facts
            .recording_layout
            .is_some_and(|layout| layout.use_dependency_id)
        {
            return Ok(self);
        }
        let Some(previous) = self.payload.get("id").filter(|value| value.is_string()) else {
            return Ok(self);
        };
        let reference = &self.facts.reference;
        let identity = Value::String(dependency_id.to_string());
        if let Some(exchange) = reference.fields().get("exchange_id") {
            if exchange != previous {
                return Ok(self);
            }
            let mut fields = reference.fields().clone();
            fields.insert("exchange_id".into(), identity.clone());
            self.facts.reference =
                traffic_model::recording::ProtocolRef::new(reference.protocol(), &fields)?;
        } else if reference.fields().get("connection_id") != self.payload.get("connection_id")
            || !reference.fields().contains_key("sequence")
        {
            return Ok(self);
        }
        self.payload["id"] = identity;
        Ok(self)
    }

    pub fn into_parts(self) -> (Value, CaptureFacts) {
        (self.payload, self.facts)
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

#[cfg(test)]
mod tests;
