//! Native evidence capabilities installed by application composition.
use std::{collections::BTreeMap, sync::Arc};

use crate::observation::{NativeSummaries, NativeSummary, TrafficInteraction};
use anyhow::{Result, ensure};
use serde_json::Value;

/// Authenticated storage is owned by the host. Protocol implementations decode
/// their native payload without depending on its physical location or reader.
pub trait RecordSource {
    fn load<T: serde::de::DeserializeOwned>(&self) -> Result<T>;
}

pub trait EvidenceAdapter: Send + Sync {
    fn schema(&self) -> &'static str;
    fn event_types(&self) -> &'static [&'static str];
    fn supports_replay(&self, event: &Value) -> bool;
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
}
