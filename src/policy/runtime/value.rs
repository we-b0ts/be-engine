use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use uuid::{Uuid, Version};

use super::config::{TimeRule, ValueValidator, parse_timezone};

pub(super) fn validate_value(actual: &Value, validator: ValueValidator) -> Result<(), String> {
    let value = actual
        .as_str()
        .ok_or_else(|| format!("{validator:?} validation requires a string value"))?;
    match validator {
        ValueValidator::NonEmpty => {
            if value.is_empty() {
                return Err("non_empty validation rejected an empty string".to_string());
            }
        }
        ValueValidator::Uuid | ValueValidator::UuidV4 => {
            let uuid = Uuid::parse_str(value)
                .map_err(|error| format!("UUID validation failed: {error}"))?;
            if validator == ValueValidator::UuidV4 && uuid.get_version() != Some(Version::Random) {
                return Err("uuid_v4 validation rejected a non-v4 UUID".to_string());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_relative_time(
    source: &Value,
    actual: &Value,
    rule: &TimeRule,
    times: crate::primary_protocol::assertion::RequestTimes,
) -> Result<(), String> {
    let source = parse_time(source, rule).map_err(|error| error.to_string())?;
    let actual = parse_time(actual, rule).map_err(|error| error.to_string())?;
    use crate::value_contract::time::{TimeMode, compare_timestamp_nanos, date_nanos};
    compare_timestamp_nanos(
        date_nanos(source),
        date_nanos(actual),
        TimeMode::PreserveRelative,
        times,
    )
    .map_err(|error| format!("request-relative time mismatch: {error:?}; fixed tolerance 5s"))
}

pub(super) fn parse_time(actual: &Value, rule: &TimeRule) -> Result<DateTime<Utc>> {
    if let Some(seconds) = actual.as_i64() {
        return DateTime::from_timestamp(seconds, 0).context("Unix timestamp is out of range");
    }
    let value = actual
        .as_str()
        .context("time validation requires a string or Unix-seconds integer")?;
    if let Some(format) = &rule.format {
        if let Ok(value) = DateTime::parse_from_str(value, format) {
            return Ok(value.with_timezone(&Utc));
        }
        let naive = NaiveDateTime::parse_from_str(value, format)
            .with_context(|| format!("time value does not match format {format:?}"))?;
        let offset = fixed_offset(rule.timezone.as_deref().unwrap_or("+00:00"))?;
        return offset
            .from_local_datetime(&naive)
            .single()
            .map(|value| value.with_timezone(&Utc))
            .context("time value is ambiguous in the configured timezone");
    }
    if let Ok(value) = DateTime::parse_from_rfc3339(value) {
        return Ok(value.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%d %H:%M:%S", "%Y%m%dT%H%M%SZ"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            let offset = fixed_offset(rule.timezone.as_deref().unwrap_or("+00:00"))?;
            return offset
                .from_local_datetime(&naive)
                .single()
                .map(|value| value.with_timezone(&Utc))
                .context("time value is ambiguous in the configured timezone");
        }
    }
    bail!("unsupported time value {value:?}; configure time.format")
}

fn fixed_offset(value: &str) -> Result<FixedOffset> {
    let seconds = parse_timezone(value)?;
    FixedOffset::east_opt(seconds).ok_or_else(|| anyhow!("timezone is out of range"))
}
