//! Native envelopes expose selected values through a host-supplied decoder.
use super::MessageSide;
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Serialize)]
#[serde(tag = "presence", rename_all = "snake_case")]
pub enum ValueObservation {
    Present {
        value: Value,
    },
    Missing {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Unavailable {
        reason: String,
    },
}

impl ValueObservation {
    pub fn missing() -> Self {
        Self::Missing { reason: None }
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }
}

/// The protocol owner supplies native bytes. Codec recognition and logical
/// selection remain with the host, independent of that native envelope.
pub trait ValueReader {
    fn select(&self, bytes: &[u8], pointer: &str) -> ValueObservation;
}

#[derive(Clone, Copy)]
pub struct ValueQuery<'a> {
    pub side: MessageSide,
    pub value_index: usize,
    pub pointer: &'a str,
}

pub struct ValueEvidence {
    pub observation: ValueObservation,
    pub document_count: usize,
    pub representation: &'static str,
    pub annotations: Map<String, Value>,
}

impl ValueEvidence {
    pub fn select(documents: &[Vec<u8>], query: ValueQuery<'_>, reader: &dyn ValueReader) -> Self {
        Self {
            observation: documents.get(query.value_index).map_or_else(
                || ValueObservation::unavailable("selected document is unavailable"),
                |bytes| reader.select(bytes, query.pointer),
            ),
            document_count: documents.len(),
            representation: "logical_value",
            annotations: Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceAdapter, EvidenceRegistry};
    use anyhow::Result;
    use serde_json::json;
    use std::sync::Arc;

    struct Custom;
    impl EvidenceAdapter for Custom {
        fn schema(&self) -> &'static str {
            "vendor/v1"
        }
        fn event_types(&self) -> &'static [&'static str] {
            &["vendor_value"]
        }
        fn supports_replay(&self, _: &Value) -> bool {
            true
        }
        fn discovery_annotations(&self, _: &Value, _: MessageSide) -> Result<Map<String, Value>> {
            Ok(Map::from_iter([(
                "native_fields".into(),
                json!(["fixture_field"]),
            )]))
        }
        fn query_value(
            &self,
            _: &Value,
            payload: &[u8],
            query: ValueQuery<'_>,
            reader: &dyn ValueReader,
        ) -> Result<Option<ValueEvidence>> {
            Ok(Some(ValueEvidence::select(
                &[payload.to_vec()],
                query,
                reader,
            )))
        }
    }
    struct Reader;
    impl ValueReader for Reader {
        fn select(&self, bytes: &[u8], pointer: &str) -> ValueObservation {
            assert_eq!(bytes, b"\x00\x01\x02");
            assert_eq!(pointer, "/logical");
            ValueObservation::Present {
                value: json!("selected"),
            }
        }
    }
    #[test]
    fn an_installed_native_evidence_owner_supplies_values_without_a_framework_branch() {
        let mut registry = EvidenceRegistry::default();
        let event = json!({"event_type":"vendor_value"});
        let query = ValueQuery {
            side: MessageSide::Response,
            value_index: 0,
            pointer: "/logical",
        };
        assert!(
            registry
                .discovery_annotations(&event, query.side)
                .unwrap()
                .is_empty()
        );
        assert!(
            registry
                .query_value(&event, b"\x00\x01\x02", query, &Reader)
                .unwrap()
                .is_none()
        );
        registry.register("vendor", Arc::new(Custom)).unwrap();
        assert_eq!(
            registry.discovery_annotations(&event, query.side).unwrap()["native_fields"],
            json!(["fixture_field"])
        );
        let result = registry
            .query_value(&event, b"\x00\x01\x02", query, &Reader)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(result.observation).unwrap(),
            json!({"presence":"present","value":"selected"})
        );
        assert_eq!(result.document_count, 1);
        assert!(
            registry
                .query_value(
                    &json!({"event_type":"other"}),
                    b"\x00\x01\x02",
                    query,
                    &Reader
                )
                .unwrap()
                .is_none()
        );
    }
}
