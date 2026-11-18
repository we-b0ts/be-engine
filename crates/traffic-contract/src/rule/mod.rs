//! Shared field semantics, independent of protocol selectors and transport.
use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize};
pub use traffic_policy::ValueScope as ClockScope;
pub use traffic_time::declaration::{
    DurationUnit, TimeAnchor, TimeContract, TimeRelation, TimestampFormat, is_schema_clock_group,
};
mod binding;
mod condition;
pub use binding::{RuleBinding, ValueRule};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldContract {
    Exact,
    /// Internal exact equality that still reserves the complete identity value.
    #[serde(skip)]
    IdentityAnchor,
    /// The inactive branch compares the selected field exactly.
    Conditional {
        when: FieldCondition,
        contract: Box<FieldContract>,
    },
    Unordered,
    Policy(traffic_policy::PolicyDefinition),
    /// Source-proven generated/derived identity, shared across one replay case.
    Identity {
        #[serde(default)]
        prefix: String,
        format: IdentityFormat,
    },
    Time {
        format: TimestampFormat,
        relation: TimeRelation,
        #[serde(skip)]
        anchor: TimeAnchor,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        utc_offset: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clock_group: Option<String>,
        #[serde(default, skip_serializing_if = "ClockScope::is_shared")]
        clock_scope: ClockScope,
    },
    Duration {
        unit: DurationUnit,
        #[serde(skip)]
        anchor: TimeAnchor,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IdentityFormatDocument", into = "IdentityFormatDocument")]
pub enum IdentityFormat {
    /// Bounded nonempty UTF-8 text, with any literal prefix checked separately.
    String,
    BoundedString(usize),
    /// Complete compact JWT shape, without inspecting business claims or verifying signatures.
    Jwt,
    Decimal,
    Uuid,
    /// Exact number of lowercase hexadecimal characters after the literal prefix.
    Hex(usize),
    /// Exact number of unpadded, URL-safe base64 characters.
    Base64Url(usize),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum IdentityFormatDocument {
    Named(IdentityFormatName),
    Hex { hex: usize },
    StringLimit { string: usize },
    Base64Url { base64url: usize },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityFormatName {
    String,
    Jwt,
    Decimal,
    Uuid,
}

impl From<IdentityFormatDocument> for IdentityFormat {
    fn from(value: IdentityFormatDocument) -> Self {
        match value {
            IdentityFormatDocument::Named(IdentityFormatName::String) => Self::String,
            IdentityFormatDocument::Named(IdentityFormatName::Jwt) => Self::Jwt,
            IdentityFormatDocument::Named(IdentityFormatName::Decimal) => Self::Decimal,
            IdentityFormatDocument::Named(IdentityFormatName::Uuid) => Self::Uuid,
            IdentityFormatDocument::Hex { hex } => Self::Hex(hex),
            IdentityFormatDocument::StringLimit { string } => Self::BoundedString(string),
            IdentityFormatDocument::Base64Url { base64url } => Self::Base64Url(base64url),
        }
    }
}

impl From<IdentityFormat> for IdentityFormatDocument {
    fn from(value: IdentityFormat) -> Self {
        match value {
            IdentityFormat::Jwt => Self::Named(IdentityFormatName::Jwt),
            IdentityFormat::String => Self::Named(IdentityFormatName::String),
            IdentityFormat::Decimal => Self::Named(IdentityFormatName::Decimal),
            IdentityFormat::Uuid => Self::Named(IdentityFormatName::Uuid),
            IdentityFormat::Hex(hex) => Self::Hex { hex },
            IdentityFormat::BoundedString(string) => Self::StringLimit { string },
            IdentityFormat::Base64Url(base64url) => Self::Base64Url { base64url },
        }
    }
}

impl FieldContract {
    pub fn registered_definition(
        &self,
        accept_exact: bool,
    ) -> Option<traffic_policy::PolicyDefinition> {
        let definition = match self {
            Self::Unordered => traffic_policy::PolicyDefinition::new("unordered"),
            Self::Policy(definition) => definition.clone(),
            Self::Identity { prefix, format } => traffic_policy::PolicyDefinition {
                options: serde_json::json!({"prefix":prefix,"format":format}),
                ..traffic_policy::PolicyDefinition::new("identity")
            },
            Self::Time { anchor, .. } => traffic_policy::PolicyDefinition {
                options: serde_json::json!({
                    "config": self.time().expect("time declaration"),
                    "clock": registered_clock(*anchor),
                    "accept_exact": accept_exact,
                }),
                ..traffic_policy::PolicyDefinition::new("time")
            },
            Self::Duration { unit, anchor } => {
                let clock = registered_clock(*anchor);
                traffic_policy::PolicyDefinition {
                    options: serde_json::json!({"unit":unit,"clock":clock,"accept_exact":accept_exact}),
                    ..traffic_policy::PolicyDefinition::new("duration")
                }
            }
            _ => return None,
        };
        Some(definition)
    }
    pub fn supports_child_rules(&self, policies: &traffic_policy::PolicyRegistry) -> Result<bool> {
        match self.unconditional() {
            Self::Unordered => Ok(true),
            Self::Policy(definition) => Ok(policies
                .prepare_definition(definition)?
                .supports_child_rules()),
            _ => Ok(false),
        }
    }
    pub fn unconditional(&self) -> &Self {
        match self {
            Self::Conditional { contract, .. } => contract,
            other => other,
        }
    }

    pub fn time(&self) -> Option<TimeContract> {
        match self {
            Self::Time {
                format,
                relation,
                anchor,
                utc_offset,
                clock_group,
                clock_scope,
            } => Some(TimeContract {
                format: *format,
                relation: *relation,
                anchor: *anchor,
                utc_offset: utc_offset.clone(),
                clock_group: clock_group.clone(),
                clock_scope: clock_scope.clone(),
            }),
            _ => None,
        }
    }
}

fn registered_clock(anchor: TimeAnchor) -> &'static str {
    match anchor {
        TimeAnchor::Observation => "observation",
        TimeAnchor::DependencyRequestStart => "dependency",
        TimeAnchor::ApiRequestStart | TimeAnchor::DependencyDelivery => "unavailable",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldCondition {
    /// The field itself (.) or one exact sibling pointer, e.g. ../status.
    pub relative_pointer: String,
    #[serde(
        default,
        deserialize_with = "present_scalar",
        skip_serializing_if = "Option::is_none"
    )]
    pub equals: Option<SourceScalar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in: Vec<SourceScalar>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SourceScalar {
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Null,
}

fn present_scalar<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SourceScalar>, D::Error> {
    SourceScalar::deserialize(deserializer).map(Some)
}
