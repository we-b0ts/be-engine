//! Open protocol identities with protocol-owned reference fields.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// Reference fields retain their original serialized names. The framework only
/// uses the protocol identity and compares the complete reference for equality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRef {
    protocol: String,
    #[serde(flatten)]
    identity: Map<String, Value>,
}

impl ProtocolRef {
    pub fn new(protocol: impl Into<String>, identity: impl Serialize) -> Result<Self> {
        let protocol = protocol.into();
        ensure!(
            !protocol.is_empty(),
            "protocol reference has an empty protocol"
        );
        let Value::Object(identity) = serde_json::to_value(identity)? else {
            anyhow::bail!("protocol reference identity must be an object");
        };
        ensure!(
            !identity.contains_key("protocol"),
            "protocol reference identity shadows its protocol"
        );
        Ok(Self { protocol, identity })
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn identity<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(Value::Object(self.identity.clone()))
            .context("invalid native protocol reference")
    }

    pub fn fields(&self) -> &Map<String, Value> {
        &self.identity
    }

    pub fn connection(protocol: &str, connection_id: Uuid, sequence: u64) -> Self {
        Self {
            protocol: protocol.into(),
            identity: json!({"connection_id": connection_id, "sequence": sequence})
                .as_object()
                .expect("native connection identity is an object")
                .clone(),
        }
    }

    pub fn exchange(protocol: &str, exchange_id: Uuid) -> Self {
        Self {
            protocol: protocol.into(),
            identity: json!({"exchange_id": exchange_id})
                .as_object()
                .expect("native exchange identity is an object")
                .clone(),
        }
    }

    pub fn observation(event_id: Uuid, kind: impl Into<String>) -> Self {
        Self {
            protocol: "observation".into(),
            identity: json!({"event_id": event_id, "kind": kind.into()})
                .as_object()
                .expect("observation identity is an object")
                .clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_and_custom_references_share_one_open_envelope() {
        let id = Uuid::from_u128(11);
        for protocol in [
            "mysql",
            "redis",
            "memcached",
            "motan",
            "kafka",
            "custom-rpc",
        ] {
            let reference = ProtocolRef::connection(protocol, id, 7);
            let value = json!({"protocol":protocol,"connection_id":id,"sequence":7});
            assert_eq!(serde_json::to_value(&reference).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<ProtocolRef>(value).unwrap(),
                reference
            );
        }
        let reference =
            ProtocolRef::new("custom", json!({"stream":"orders", "offset":17})).unwrap();
        assert_eq!(reference.protocol(), "custom");
        assert_eq!(reference.fields()["offset"], 17);
        assert!(ProtocolRef::new("custom", json!({"protocol":"other"})).is_err());
    }
}
