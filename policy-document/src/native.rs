//! Closed contracts for stateful identities, signatures and acquisition effects.
//! The compiler retains these as typed effects; protocol owners never reparse YAML.

use serde::{Deserialize, Serialize};

use super::{Proof, Rule};
pub use traffic_policy_schema::native::*;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PolicyRule {
    Value(Box<Rule>),
    Native(Box<NativeRule>),
}

// Dispatch by the explicit native `effect` field rather than an untagged trial
// decoder, so worker errors name the malformed field in the selected rule.
impl<'de> Deserialize<'de> for PolicyRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_yaml::Value::deserialize(deserializer)?;
        let id = value
            .get("id")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("<missing-id>")
            .to_owned();
        if value.get("effect").is_none() {
            return Err(serde::de::Error::custom(
                "API/resource field rules are retired; declare formats in root json.fields or mysql.tables",
            ));
        }
        crate::authoring::expand_rule(&mut value, None)
            .map_err(|error| serde::de::Error::custom(format!("rule {id:?}: {error:#}")))?;
        serde_yaml::from_value::<NativeRule>(value)
            .map(|rule| Self::Native(Box::new(rule)))
            .map_err(|error| serde::de::Error::custom(format!("rule {id:?}: {error}")))
    }
}

impl PolicyRule {
    pub fn as_value(&self) -> Option<&Rule> {
        if let Self::Value(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn as_value_mut(&mut self) -> Option<&mut Rule> {
        if let Self::Value(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn as_native(&self) -> Option<&NativeRule> {
        if let Self::Native(rule) = self {
            Some(rule)
        } else {
            None
        }
    }
    pub fn id(&self) -> &str {
        match self {
            Self::Value(rule) => &rule.id,
            Self::Native(rule) => &rule.id,
        }
    }

    pub fn proof(&self) -> Option<&Proof> {
        match self {
            Self::Value(rule) => Some(&rule.proof),
            Self::Native(rule) => rule.proof.as_ref(),
        }
    }
}

impl From<Rule> for PolicyRule {
    fn from(rule: Rule) -> Self {
        Self::Value(Box::new(rule))
    }
}

impl From<NativeRule> for PolicyRule {
    fn from(rule: NativeRule) -> Self {
        Self::Native(Box::new(rule))
    }
}
