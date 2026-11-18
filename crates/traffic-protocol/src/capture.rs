//! Protocol-supplied capture facts consumed by lifecycle and persistence owners.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use traffic_model::{DependencyExchangeOutcome, recording::ProtocolRef};

mod snapshot;
pub use snapshot::CaptureSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticRequirement {
    Observation,
    Dependency,
    Mandatory,
}

#[derive(Clone)]
pub struct CaptureFacts {
    pub reference: ProtocolRef,
    pub outcome: DependencyExchangeOutcome,
    pub terminal: String,
    pub complete: bool,
    pub semantic: SemanticRequirement,
    pub debug: bool,
    pub case_dependency: bool,
    pub traffic_error: bool,
}

impl CaptureFacts {
    pub fn observation(reference: ProtocolRef) -> Self {
        Self {
            reference,
            outcome: DependencyExchangeOutcome::Response,
            terminal: "observation".into(),
            complete: true,
            semantic: SemanticRequirement::Observation,
            debug: false,
            case_dependency: true,
            traffic_error: false,
        }
    }

    pub fn dependency(reference: ProtocolRef, terminal: impl Into<String>, complete: bool) -> Self {
        Self {
            terminal: terminal.into(),
            complete,
            semantic: SemanticRequirement::Dependency,
            ..Self::observation(reference)
        }
    }

    pub fn semantic_required(&self, preflight_probe: bool) -> bool {
        self.semantic == SemanticRequirement::Mandatory
            || (self.semantic == SemanticRequirement::Dependency && !preflight_probe)
    }
}

/// Native types describe complete capture and local effects. The framework
/// assigns ownership, clocks and physical recording identity separately.
pub trait CaptureEvidence: Serialize + Send + Sync {
    fn event_type(&self) -> &'static str;
    fn capture_facts(&self) -> CaptureFacts;
}

pub fn payload(event: &impl CaptureEvidence) -> Result<Value> {
    Ok(CaptureSnapshot::capture(event)?.into_parts().0)
}

pub(crate) fn native_payload(event: &impl CaptureEvidence) -> Result<Value> {
    let mut payload = serde_json::to_value(event)?;
    let object = payload
        .as_object_mut()
        .context("capture payload must be an object")?;
    ensure!(
        ["recording_id", "capture", "capture_complete"]
            .iter()
            .all(|field| !object.contains_key(*field)),
        "native payload shadows the recording envelope"
    );
    if let Some(kind) = object.get("event_type") {
        ensure!(
            kind.as_str() == Some(event.event_type()),
            "capture payload has a conflicting native event type"
        );
    } else {
        object.insert("event_type".into(), event.event_type().into());
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Serialize)]
    #[serde(transparent)]
    struct Event(Value);
    impl CaptureEvidence for Event {
        fn event_type(&self) -> &'static str {
            "custom_event"
        }
        fn capture_facts(&self) -> CaptureFacts {
            CaptureFacts::observation(ProtocolRef::new("custom", json!({"request":7})).unwrap())
        }
    }

    #[test]
    fn native_payload_types_retain_the_framework_envelope_and_one_event_tag() {
        assert_eq!(
            payload(&Event(json!({"value":"native"}))).unwrap(),
            json!({"event_type":"custom_event","value":"native"})
        );
        assert!(payload(&Event(json!({"event_type":"another_event"}))).is_err());
        for field in ["recording_id", "capture", "capture_complete"] {
            let mut native = json!({});
            native[field] = json!("native");
            assert!(payload(&Event(native)).is_err());
        }
    }

    #[test]
    fn an_unparsed_transport_obligation_survives_the_preflight_probe_filter() {
        let reference = ProtocolRef::new("custom", json!({"request":7})).unwrap();
        let mut facts = CaptureFacts::dependency(reference, "response", true);
        assert!(facts.semantic_required(false));
        assert!(!facts.semantic_required(true));
        facts.semantic = SemanticRequirement::Mandatory;
        assert!(facts.semantic_required(true));
    }
}
