//! Format-specific validation and relative translation of Redis JSON timestamps.
use super::RedisTimestampFormat;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Datelike, FixedOffset, SecondsFormat, TimeZone, Utc};
use serde_json::Value;

pub(super) fn validate(value: &Value, format: RedisTimestampFormat) -> Result<()> {
    match format {
        RedisTimestampFormat::UnixSeconds | RedisTimestampFormat::UnixMilliseconds => {
            integer(value)?;
        }
        RedisTimestampFormat::Rfc3339 => {
            rfc3339(value)?;
        }
    }
    Ok(())
}

pub(super) fn shift(
    value: &Value,
    format: RedisTimestampFormat,
    recorded_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Value> {
    let offset = match format {
        RedisTimestampFormat::UnixSeconds => now
            .timestamp()
            .checked_sub(recorded_at.timestamp())
            .context("Redis time-shift seconds overflow")?,
        RedisTimestampFormat::UnixMilliseconds => now
            .timestamp_millis()
            .checked_sub(recorded_at.timestamp_millis())
            .context("Redis time-shift milliseconds overflow")?,
        RedisTimestampFormat::Rfc3339 => {
            let timestamp = rfc3339(value)?;
            // Check local date arithmetic before formatting, including the four-digit
            // RFC3339 year range. The fixed offset has no daylight-saving changes.
            let local = timestamp
                .naive_local()
                .checked_add_signed(now.signed_duration_since(recorded_at))
                .context("Redis time-shift RFC3339 timestamp overflow")?;
            ensure!(
                (0..=9999).contains(&local.year()),
                "Redis time-shift RFC3339 timestamp is outside the four-digit year range"
            );
            let shifted = timestamp
                .offset()
                .from_local_datetime(&local)
                .single()
                .context("Redis time-shift RFC3339 timestamp overflow")?;
            let use_z = value
                .as_str()
                .is_some_and(|text| text.ends_with(['Z', 'z']));
            return Ok(Value::String(
                shifted.to_rfc3339_opts(SecondsFormat::AutoSi, use_z),
            ));
        }
    };
    Ok(Value::from(
        integer(value)?
            .checked_add(offset)
            .context("Redis time-shift timestamp overflow")?,
    ))
}

fn integer(value: &Value) -> Result<i64> {
    value
        .as_i64()
        .context("Redis time-shift requires integer timestamps for Unix formats")
}

fn rfc3339(value: &Value) -> Result<DateTime<FixedOffset>> {
    let text = value
        .as_str()
        .context("Redis time-shift requires RFC3339 timestamp strings")?;
    DateTime::parse_from_rfc3339(text)
        .context("Redis time-shift requires a valid RFC3339 timestamp with a timezone")
}
