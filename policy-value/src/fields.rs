//! Carrier-independent authored formats and Source-selected field policies.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_contract::rule::{
    ClockScope, FieldContract, IdentityFormat, TimeAnchor, TimeContract, TimeRelation,
    TimestampFormat,
};
use traffic_policy::PolicyRegistry;
mod plan;
mod prepared;
mod selectors;
pub use plan::{FieldPlan, FieldSelectors, PreparedJsonFields, pointer_pattern};
mod template;
pub use template::GlobalTemplateFormat;
mod time;
pub use time::TimePolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalUrlFormat {
    AwsSigv4,
    Url,
}

pub const GLOBAL_JSON_ID: &str = "global.json";

#[derive(Debug, Clone)]
pub struct SelectedGlobalField {
    pub pattern: String,
    pub pointer: String,
    pub contract: FieldContract,
    pub rule_id: &'static str,
    pub origin: FieldOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOrigin {
    Declared,
    Inferred,
}

#[derive(Debug, Clone)]
pub struct MatchedFormatField {
    pub pattern: String,
    pub pointer: String,
}

/// A physical carrier supplies a value while the selected format chooses its contract.
pub trait ScalarFormat: Send + Sync {
    fn select(
        &self,
        source: &Value,
        clock: Option<chrono::DateTime<chrono::Utc>>,
        policies: &PolicyRegistry,
    ) -> Result<FieldContract>;
}

impl ScalarFormat for GlobalField {
    fn select(
        &self,
        source: &Value,
        clock: Option<chrono::DateTime<chrono::Utc>>,
        policies: &PolicyRegistry,
    ) -> Result<FieldContract> {
        self.select_contract_with_registry(source, clock, policies)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GlobalField {
    Policy(traffic_policy::PolicyDefinition),
    Time {
        formats: Vec<GlobalTimeFormat>,
    },
    Identity {
        formats: Vec<GlobalIdentityFormat>,
    },
    Duration {
        formats: Vec<traffic_contract::rule::DurationUnit>,
    },
    Url {
        formats: Vec<GlobalUrlFormat>,
    },
    Template {
        formats: Vec<GlobalTemplateFormat>,
    },
    Jwt {
        #[serde(
            default = "default_signature",
            skip_serializing_if = "is_default_signature"
        )]
        signature: String,
    },
    Unordered,
}

fn default_signature() -> String {
    "default".into()
}
fn is_default_signature(name: &str) -> bool {
    name == "default"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "TimeFormatDocument", into = "TimeFormatDocument")]
pub struct GlobalTimeFormat {
    pub format: TimestampFormat,
    pub utc_offset: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum TimeFormatDocument {
    Named(TimestampFormat),
    Detailed {
        format: TimestampFormat,
        utc_offset: String,
    },
}

impl From<TimeFormatDocument> for GlobalTimeFormat {
    fn from(value: TimeFormatDocument) -> Self {
        match value {
            TimeFormatDocument::Named(format) => Self {
                format,
                utc_offset: None,
            },
            TimeFormatDocument::Detailed { format, utc_offset } => Self {
                format,
                utc_offset: Some(utc_offset),
            },
        }
    }
}

impl From<GlobalTimeFormat> for TimeFormatDocument {
    fn from(value: GlobalTimeFormat) -> Self {
        match value.utc_offset {
            Some(utc_offset) => Self::Detailed {
                format: value.format,
                utc_offset,
            },
            None => Self::Named(value.format),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "IdentityFormatDocument", into = "IdentityFormatDocument")]
pub struct GlobalIdentityFormat {
    pub prefix: String,
    pub format: IdentityFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum IdentityFormatDocument {
    Named(IdentityFormat),
    Hex {
        #[serde(default)]
        prefix: String,
        hex: usize,
    },
    Base64Url {
        #[serde(default)]
        prefix: String,
        base64url: usize,
    },
    Prefixed {
        prefix: String,
        format: IdentityFormat,
    },
}

impl From<IdentityFormatDocument> for GlobalIdentityFormat {
    fn from(value: IdentityFormatDocument) -> Self {
        match value {
            IdentityFormatDocument::Named(format) => Self {
                prefix: String::new(),
                format,
            },
            IdentityFormatDocument::Hex { prefix, hex } => Self {
                prefix,
                format: IdentityFormat::Hex(hex),
            },
            IdentityFormatDocument::Base64Url { prefix, base64url } => Self {
                prefix,
                format: IdentityFormat::Base64Url(base64url),
            },
            IdentityFormatDocument::Prefixed { prefix, format } => Self { prefix, format },
        }
    }
}

impl From<GlobalIdentityFormat> for IdentityFormatDocument {
    fn from(value: GlobalIdentityFormat) -> Self {
        if value.prefix.is_empty() {
            return Self::Named(value.format);
        }
        match value.format {
            IdentityFormat::Hex(hex) => Self::Hex {
                prefix: value.prefix,
                hex,
            },
            IdentityFormat::Base64Url(base64url) => Self::Base64Url {
                prefix: value.prefix,
                base64url,
            },
            format => Self::Prefixed {
                prefix: value.prefix,
                format,
            },
        }
    }
}

impl GlobalTimeFormat {
    pub fn contract(&self) -> FieldContract {
        FieldContract::Time {
            format: self.format,
            relation: TimeRelation::PreserveOffset,
            anchor: TimeAnchor::Observation,
            utc_offset: self.utc_offset.clone(),
            // Every physical occurrence owns its clock observations; an authored
            // global field declaration does not join unrelated business clocks.
            clock_group: None,
            clock_scope: ClockScope::default(),
        }
    }
}

impl GlobalField {
    pub fn is_identity(&self) -> bool {
        matches!(self, Self::Identity { .. } | Self::Jwt { .. })
    }
    pub fn validate_with_registry(&self, policies: &PolicyRegistry) -> Result<()> {
        match self {
            Self::Policy(definition) => {
                policies.prepare_definition(definition)?;
            }
            Self::Time { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "time requires 1..16 formats"
                );
                for format in formats {
                    let contract = format.contract().time().expect("time contract");
                    ensure!(
                        format.format != TimestampFormat::CalendarDate
                            || format.utc_offset.is_some(),
                        "calendar_date requires an explicit format utc_offset"
                    );
                    ensure!(
                        format.utc_offset.is_none()
                            || matches!(
                                format.format,
                                TimestampFormat::CalendarDate
                                    | TimestampFormat::SqlDatetime
                                    | TimestampFormat::Iso8601Naive
                            ),
                        "only calendar and naive time formats accept utc_offset"
                    );
                    contract.offset()?;
                    let definition = format
                        .contract()
                        .registered_definition(true)
                        .expect("timestamp has a registered implementation");
                    policies.prepare_definition(&definition)?;
                }
            }
            Self::Identity { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "identity requires 1..16 formats"
                );
                for format in formats {
                    ensure!(
                        format.prefix.len() <= 128 && format.prefix.is_ascii(),
                        "identity prefix requires at most 128 ASCII bytes"
                    );
                    match format.format {
                        IdentityFormat::Hex(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity hex requires 1..1024 characters"
                        ),
                        IdentityFormat::BoundedString(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity string length requires 1..1024 bytes"
                        ),
                        IdentityFormat::Base64Url(length) => ensure!(
                            (1..=1024).contains(&length),
                            "identity base64url requires 1..1024 characters"
                        ),
                        IdentityFormat::Jwt => anyhow::bail!(
                            "JWT identity syntax is retired; use kind: jwt with a named signatures definition"
                        ),
                        _ => {}
                    }
                    let definition = FieldContract::Identity {
                        prefix: format.prefix.clone(),
                        format: format.format,
                    }
                    .registered_definition(false)
                    .expect("identity has a registered implementation");
                    policies.prepare_definition(&definition)?;
                }
            }
            Self::Url { formats } => {
                ensure!(formats.len() == 1, "URL requires one known protocol format")
            }
            Self::Template { formats } => {
                ensure!(
                    !formats.is_empty() && formats.len() <= 16,
                    "template requires 1..16 formats"
                );
                for format in formats {
                    format.validate_with_registry(policies)?;
                }
            }
            Self::Jwt { signature } => ensure!(
                !signature.is_empty() && signature.len() <= 128,
                "JWT requires a bounded named signature"
            ),
            Self::Duration { formats } => {
                ensure!(
                    formats.len() == 1,
                    "duration requires exactly one unambiguous unit format"
                );
                let definition = FieldContract::Duration {
                    unit: formats[0],
                    anchor: TimeAnchor::Observation,
                }
                .registered_definition(true)
                .expect("duration has a registered implementation");
                policies.prepare_definition(&definition)?;
            }
            Self::Unordered => {
                policies.prepare("unordered", &traffic_value::Value::Null)?;
            }
        }
        Ok(())
    }
}

pub fn validate_fields(
    fields: &BTreeMap<String, GlobalField>,
    time: &TimePolicy,
    policies: &PolicyRegistry,
) -> Result<()> {
    time.offset()?;
    ensure!(
        fields.len() <= 4096,
        "json.fields accepts at most 4096 fields"
    );
    for (pointer, field) in fields {
        traffic_contract::path::validate_pointer(pointer, true)?;
        field
            .validate_with_registry(policies)
            .with_context(|| format!("invalid global JSON field {pointer:?}"))?;
    }
    let paths = fields.keys().collect::<Vec<_>>();
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            ensure!(
                !overlaps(left, right),
                "global JSON selectors {left:?} and {right:?} overlap"
            );
        }
    }
    Ok(())
}

fn overlaps(left: &str, right: &str) -> bool {
    let left = left.split('/').collect::<Vec<_>>();
    let right = right.split('/').collect::<Vec<_>>();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| *a == b || *a == "*" || b == "*")
}
