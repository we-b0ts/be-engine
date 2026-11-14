//! Native evidence capabilities installed by application composition.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Result, ensure};
use serde_json::Value;

pub trait EvidenceAdapter: Send + Sync {
    fn schema(&self) -> &'static str;
    fn event_types(&self) -> &'static [&'static str];
    fn supports_replay(&self, event: &Value) -> bool;
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
        let index = self.registrations.len();
        for kind in adapter.event_types() {
            ensure!(!kind.is_empty(), "native event type is empty");
            ensure!(
                events.insert(kind, index).is_none(),
                "native event type is already registered"
            );
        }
        self.registrations.push(Registration {
            name: name.into(),
            adapter,
        });
        self.events = events;
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
        if event["replay_safe"] == false
            || event["capture_complete"] == false
            || event["_capture_complete"] == false
        {
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

    /// Part of off-path inventory cache identity, independent of payload bytes.
    pub fn revisions(&self) -> BTreeMap<&str, &str> {
        self.registrations
            .iter()
            .map(|entry| (entry.name.as_str(), entry.adapter.schema()))
            .collect()
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
        for field in [
            "replay_safe",
            "capture_complete",
            "_capture_complete",
            "native_complete",
        ] {
            let mut incomplete = event.clone();
            incomplete[field] = json!(false);
            assert!(!registry.supports_replay(&incomplete));
        }
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
