//! Shared field semantics, independent of protocol selectors and transport.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
mod clock_scope;
pub use clock_scope::ClockScope;
mod condition;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FieldContract {
    /// Internal exact equality that still reserves the complete identity value.
    #[serde(skip)]
    IdentityAnchor,
    /// The inactive branch compares the selected field exactly.
    Conditional {
        when: FieldCondition,
        contract: Box<FieldContract>,
    },
    Unordered,
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
#[serde(deny_unknown_fields)]
pub struct TimeContract {
    pub format: TimestampFormat,
    pub relation: TimeRelation,
    #[serde(skip)]
    pub anchor: TimeAnchor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_group: Option<String>,
    #[serde(default, skip_serializing_if = "ClockScope::is_shared")]
    pub clock_scope: ClockScope,
}

impl TimeContract {
    pub fn offset(&self) -> Result<Option<chrono::FixedOffset>> {
        let Some(value) = &self.utc_offset else {
            // A shared civil offset cancels in a relative comparison and in
            // delivery translation. UTC is only a neutral arithmetic origin.
            if self.relation == TimeRelation::PreserveOffset
                && matches!(
                    self.format,
                    TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime
                )
            {
                return Ok(chrono::FixedOffset::east_opt(0));
            }
            return Ok(None);
        };
        ensure!(
            value.len() == 6
                && matches!(value.as_bytes()[0], b'+' | b'-')
                && value.as_bytes()[3] == b':'
                && value.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
                && value.as_bytes()[4..6].iter().all(u8::is_ascii_digit),
            "utc_offset requires explicit +/-HH:MM"
        );
        let hours: i32 = value[1..3].parse()?;
        let minutes: i32 = value[4..6].parse()?;
        ensure!(
            hours < 24 && minutes < 60,
            "utc_offset is outside a fixed day's range"
        );
        let sign = if value.starts_with('-') { -1 } else { 1 };
        Ok(Some(
            chrono::FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60))
                .context("invalid fixed utc_offset")?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
    UnixMicroseconds,
    Rfc3339,
    AmzDate,
    Iso8601Naive,
    SqlDatetime,
    /// A civil YYYY-MM-DD value relative to the request's declared local day.
    CalendarDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRelation {
    RequestWindow,
    PreserveOffset,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TimeAnchor {
    /// The independently observed event being compared: dependency request
    /// initiation or primary response completion, selected by the caller.
    #[default]
    #[serde(rename = "observation")]
    Observation,
    #[serde(rename = "case.request_start")]
    ApiRequestStart,
    #[serde(rename = "dependency.request_start")]
    DependencyRequestStart,
    #[serde(rename = "dependency.response_delivery")]
    DependencyDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurationUnit {
    Seconds,
    Milliseconds,
    Microseconds,
    Minutes,
    Hours,
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

/// Automatic groups carry no authored cross-field clock relationship.
pub fn is_schema_clock_group(group: &str) -> bool {
    group.strip_prefix("schema.").is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
