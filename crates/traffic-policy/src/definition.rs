use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// A persisted invocation of one independently registered policy implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDefinition {
    pub id: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(
        default,
        deserialize_with = "options",
        skip_serializing_if = "serde_json::Value::is_null"
    )]
    pub options: serde_json::Value,
}

fn options<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<serde_json::Value, D::Error> {
    let value = traffic_value::Value::deserialize(deserializer)?;
    serde_json::to_value(value).map_err(serde::de::Error::custom)
}

fn default_version() -> u32 {
    1
}

impl PolicyDefinition {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: 1,
            options: serde_json::Value::Null,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "policy requires a bounded implementation identity"
        );
        ensure!(self.version > 0, "policy version is zero");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_options_reject_duplicate_members_and_preserve_provider_owned_literals() {
        assert!(
            serde_json::from_str::<PolicyDefinition>(
                r#"{"id":"fixture","options":{"unit":1,"unit":2}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PolicyDefinition>(
                r#"{"id":"fixture","options":{"nested":{"unit":1,"unit":2}}}"#
            )
            .is_err()
        );
        let definition: PolicyDefinition = serde_json::from_str(r#"{"id":"fixture","version":3,"options":{"proof":{"kind":"literal"},"items":[1,"1",null]}}"#).unwrap();
        let encoded = serde_json::to_string(&definition).unwrap();
        assert_eq!(
            serde_json::from_str::<PolicyDefinition>(&encoded).unwrap(),
            definition
        );
        assert_eq!(definition.options["proof"]["kind"], "literal");
    }
}
