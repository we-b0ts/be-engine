//! Native evidence capabilities installed by application composition.
use std::{collections::BTreeMap, sync::Arc};

use crate::observation::{NativeSummaries, NativeSummary, RecordingSummary, TrafficInteraction};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_model::recording::ProtocolRef;
mod payload;
#[cfg(test)]
mod payload_tests;
mod recording_summary;
mod timing;
pub use payload::{EvidenceSecrets, MessageSide};
pub use recording_summary::RecordingSummaries;
pub use timing::SourceTiming;

/// Authenticated storage is owned by the host. Protocol implementations decode
/// their native payload without depending on its physical location or reader.
pub trait RecordSource {
    fn load<T: serde::de::DeserializeOwned>(&self) -> Result<T>;

    /// Authenticated encoded size, when the storage owner can supply it.
    /// Bounded native projections can reject unavailable or oversized records
    /// before reading their payloads.
    fn byte_len(&self) -> Option<u64> {
        None
    }
}

pub trait EvidenceAdapter: Send + Sync {
    fn schema(&self) -> &'static str;
    fn event_types(&self) -> &'static [&'static str];
    fn source_payload(
        &self,
        _protocol: &str,
        _event: &Value,
        _side: MessageSide,
        _secrets: &dyn EvidenceSecrets,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn supports_replay(&self, event: &Value) -> bool;
    fn include_in_recording_summary(&self, event: &Value) -> bool {
        event["capture"]["semantic_required"] != false
    }
    fn recording_summary(&self) -> Option<Box<dyn RecordingSummary>> {
        None
    }
    fn recording_safety_issue(&self, _event: &Value) -> Option<String> {
        None
    }
    fn supports_input_timing(&self, _event_type: &str) -> bool {
        false
    }
    fn source_timing(&self, _event: &Value) -> SourceTiming {
        SourceTiming::Unsupported
    }
    fn connection_endpoint(&self, event: &Value) -> Result<Option<crate::connection::Endpoint>> {
        let Some(endpoint) = self
            .interaction(event)
            .and_then(|interaction| interaction.endpoint)
        else {
            return Ok(None);
        };
        let authority = endpoint.parse::<http::uri::Authority>()?;
        Ok(authority
            .port_u16()
            .map(|port| crate::connection::Endpoint {
                host: crate::observation::normalize_host(authority.host()),
                port,
            }))
    }
    fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        capture_reference(event)
    }
    fn supports_interaction_inventory(&self) -> bool {
        true
    }
    fn interaction(&self, _event: &Value) -> Option<TrafficInteraction> {
        None
    }
    fn process_summary_types(&self) -> &'static [&'static str] {
        &[]
    }
    fn process_summary_key(&self, _event: &Value) -> Option<&'static str> {
        None
    }
    fn process_summary(&self, _name: &str) -> Option<Box<dyn NativeSummary>> {
        None
    }
}

fn capture_reference(event: &Value) -> Result<Option<ProtocolRef>> {
    if event["capture"]["semantic_required"] != true {
        return Ok(None);
    }
    let exchange_id = event["capture"]["exchange_id"]
        .as_str()
        .context("Source dependency has no framework capture identity")?
        .parse()?;
    Ok(Some(ProtocolRef::exchange("capture", exchange_id)))
}

#[derive(Clone)]
struct Registration {
    name: String,
    adapter: Arc<dyn EvidenceAdapter>,
}

/// Frozen with the connection providers. Unknown events retain an unsupported
/// obligation, including when no parser is installed for their native payload.
#[derive(Clone, Default)]
pub struct EvidenceRegistry {
    registrations: Vec<Registration>,
    events: BTreeMap<&'static str, usize>,
    summaries: BTreeMap<&'static str, usize>,
}

impl std::fmt::Debug for EvidenceRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_map().entries(self.revisions()).finish()
    }
}

impl EvidenceRegistry {
    pub fn source_payload(
        &self,
        protocol: &str,
        event: &Value,
        side: MessageSide,
        secrets: &dyn EvidenceSecrets,
    ) -> Result<Option<Vec<u8>>> {
        match event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
        {
            Some(index) => self.registrations[*index]
                .adapter
                .source_payload(protocol, event, side, secrets),
            None => Ok(None),
        }
    }
    pub fn connection_endpoint(
        &self,
        event: &Value,
    ) -> Result<Option<crate::connection::Endpoint>> {
        match event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
        {
            Some(index) => self.registrations[*index]
                .adapter
                .connection_endpoint(event),
            None => Ok(None),
        }
    }
    pub fn recording_safety_issue(&self, event: &Value) -> Option<String> {
        self.registrations
            .iter()
            .find_map(|entry| entry.adapter.recording_safety_issue(event))
    }
    pub fn supports_input_timing(&self, event_type: &str) -> bool {
        self.events.get(event_type).is_some_and(|index| {
            self.registrations[*index]
                .adapter
                .supports_input_timing(event_type)
        })
    }

    pub fn source_timing(&self, event: &Value) -> SourceTiming {
        event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
            .map_or(SourceTiming::Unsupported, |index| {
                self.registrations[*index].adapter.source_timing(event)
            })
    }
    pub fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
        if event["capture"]["semantic_required"] == false {
            return Ok(None);
        }
        match event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
        {
            Some(index) => self.registrations[*index].adapter.finite_reference(event),
            None => capture_reference(event),
        }
    }

    pub fn supports_interaction_inventory(&self, event: &Value) -> bool {
        if event["capture"]["semantic_required"] == false {
            return true;
        }
        event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
            .is_some_and(|index| {
                self.registrations[*index]
                    .adapter
                    .supports_interaction_inventory()
            })
    }

    pub fn register(&mut self, name: &str, adapter: Arc<dyn EvidenceAdapter>) -> Result<()> {
        ensure!(!name.is_empty(), "evidence adapter name is empty");
        ensure!(
            !adapter.schema().is_empty(),
            "evidence adapter schema is empty"
        );
        ensure!(
            self.registrations.iter().all(|entry| entry.name != name),
            "evidence adapter is already registered"
        );
        let mut events = self.events.clone();
        let mut summaries = self.summaries.clone();
        let index = self.registrations.len();
        for kind in adapter.event_types() {
            ensure!(!kind.is_empty(), "native event type is empty");
            ensure!(
                events.insert(kind, index).is_none(),
                "native event type is already registered"
            );
        }
        for name in adapter.process_summary_types() {
            ensure!(
                ![
                    "name",
                    "interactions",
                    "bootstrap_interactions",
                    "runtime_interactions",
                    "other_phase_interactions",
                    "unresolved_interactions",
                    "observations",
                    "omitted_interactions",
                    "truncated"
                ]
                .contains(name),
                "native summary shadows framework process counters"
            );
            ensure!(
                !name.is_empty() && summaries.insert(name, index).is_none(),
                "native summary type is empty or already registered"
            );
        }
        self.registrations.push(Registration {
            name: name.into(),
            adapter,
        });
        self.events = events;
        self.summaries = summaries;
        Ok(())
    }

    pub(crate) fn replace(
        &mut self,
        old_name: &str,
        name: &str,
        adapter: Option<Arc<dyn EvidenceAdapter>>,
    ) -> Result<()> {
        let mut replacement = Self::default();
        for entry in &self.registrations {
            if entry.name != old_name {
                replacement.register(&entry.name, entry.adapter.clone())?;
            }
        }
        if let Some(adapter) = adapter {
            replacement.register(name, adapter)?;
        }
        *self = replacement;
        Ok(())
    }

    pub fn supports_replay(&self, event: &Value) -> bool {
        if event["capture_complete"] == false || event["_capture_complete"] == false {
            return false;
        }
        let Some(index) = event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
        else {
            return false;
        };
        self.registrations[*index].adapter.supports_replay(event)
    }

    pub fn owner(&self, event: &Value) -> Option<&str> {
        let index = self.events.get(event["event_type"].as_str()?)?;
        Some(&self.registrations[*index].name)
    }

    /// Part of off-path inventory cache identity, independent of payload bytes.
    pub fn revisions(&self) -> BTreeMap<&str, &str> {
        self.registrations
            .iter()
            .map(|entry| (entry.name.as_str(), entry.adapter.schema()))
            .collect()
    }

    pub fn interaction(&self, event: &Value) -> Option<TrafficInteraction> {
        let index = self.events.get(event["event_type"].as_str()?)?;
        self.registrations[*index].adapter.interaction(event)
    }

    pub fn observe_process(
        &self,
        summaries: &mut NativeSummaries,
        event: &Value,
        endpoint: Option<&str>,
    ) -> Result<()> {
        let Some(index) = event["event_type"]
            .as_str()
            .and_then(|kind| self.events.get(kind))
        else {
            return Ok(());
        };
        let adapter = &self.registrations[*index].adapter;
        let Some(name) = adapter.process_summary_key(event) else {
            return Ok(());
        };
        ensure!(
            self.summaries.get(name) == Some(index),
            "native process summary has no registered owner"
        );
        if !summaries.values.contains_key(name) {
            let summary = adapter
                .process_summary(name)
                .ok_or_else(|| anyhow::anyhow!("native process summary has no accumulator"))?;
            summaries.values.insert(name.into(), summary);
        }
        summaries
            .values
            .get_mut(name)
            .expect("native summary was initialized")
            .observe(event, endpoint);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct CustomEvidence {
        event: &'static [&'static str],
    }

    impl EvidenceAdapter for CustomEvidence {
        fn schema(&self) -> &'static str {
            "custom/v1"
        }
        fn event_types(&self) -> &'static [&'static str] {
            self.event
        }
        fn supports_replay(&self, event: &Value) -> bool {
            event["native_complete"] == true
        }
    }

    #[test]
    fn unknown_native_events_acquire_support_only_from_their_registered_owner() {
        let event = json!({"event_type":"custom_call", "native_complete":true});
        let mut registry = EvidenceRegistry::default();
        assert!(!registry.supports_replay(&event));
        registry
            .register(
                "custom",
                Arc::new(CustomEvidence {
                    event: &["custom_call"],
                }),
            )
            .unwrap();
        assert!(registry.supports_replay(&event));
        for field in ["capture_complete", "_capture_complete", "native_complete"] {
            let mut incomplete = event.clone();
            incomplete[field] = json!(false);
            assert!(!registry.supports_replay(&incomplete));
        }
        let mut native_field = event;
        native_field["replay_safe"] = json!(false);
        assert!(registry.supports_replay(&native_field));
    }

    #[test]
    fn duplicate_event_registration_and_failed_replacement_preserve_the_original_registry() {
        let mut registry = EvidenceRegistry::default();
        registry
            .register(
                "first",
                Arc::new(CustomEvidence {
                    event: &["custom_call"],
                }),
            )
            .unwrap();
        registry
            .register(
                "second",
                Arc::new(CustomEvidence {
                    event: &["other_call"],
                }),
            )
            .unwrap();
        let before = registry
            .revisions()
            .into_iter()
            .map(|(name, schema)| (name.to_owned(), schema.to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert!(
            registry
                .register(
                    "third",
                    Arc::new(CustomEvidence {
                        event: &["new_call", "custom_call"]
                    })
                )
                .is_err()
        );
        assert!(
            registry
                .replace(
                    "first",
                    "first",
                    Some(Arc::new(CustomEvidence {
                        event: &["other_call"]
                    }))
                )
                .is_err()
        );
        let after = registry
            .revisions()
            .into_iter()
            .map(|(name, schema)| (name.to_owned(), schema.to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(before, after);
        assert!(
            !registry.supports_replay(&json!({"event_type":"new_call","native_complete":true}))
        );
        assert!(
            registry.supports_replay(&json!({"event_type":"custom_call","native_complete":true}))
        );
    }

    #[test]
    fn finite_references_use_the_installed_native_evidence_owner() {
        struct NativeReferences;
        impl EvidenceAdapter for NativeReferences {
            fn schema(&self) -> &'static str {
                "custom-reference/v1"
            }
            fn event_types(&self) -> &'static [&'static str] {
                &["custom_delivery"]
            }
            fn supports_replay(&self, _: &Value) -> bool {
                true
            }
            fn finite_reference(&self, event: &Value) -> Result<Option<ProtocolRef>> {
                Ok(Some(ProtocolRef::new(
                    "custom",
                    json!({
                        "stream":event["native_stream"], "offset":event["native_offset"]
                    }),
                )?))
            }
        }
        let event =
            json!({"event_type":"custom_delivery", "native_stream":"orders", "native_offset":17});
        let mut registry = EvidenceRegistry::default();
        assert!(registry.finite_reference(&event).unwrap().is_none());
        assert!(!registry.supports_interaction_inventory(&event));
        registry
            .register("custom", Arc::new(NativeReferences))
            .unwrap();
        assert_eq!(
            serde_json::to_value(registry.finite_reference(&event).unwrap()).unwrap(),
            json!({"protocol":"custom", "stream":"orders", "offset":17})
        );
        assert!(registry.supports_interaction_inventory(&event));
        let mut observation = event;
        observation["capture"] = json!({"semantic_required":false});
        assert!(registry.finite_reference(&observation).unwrap().is_none());
    }
}
