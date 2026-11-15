//! Exact request timestamp parsing and independently captured clock validation.
use super::*;
use crate::value_contract::time::{self, TimeMode, TimestampFormat};
use chrono::{FixedOffset, Timelike};
use config::{RequestTimestampFormat as Format, TimeField};

const AUTOMATIC_REDIS_GROUP_PREFIX: &str = "auto-redis-argument-";

/// A validated timestamp pair and its declared or Source-derived relationship.
#[derive(Debug, Clone)]
pub(super) struct ComparedTime {
    pub(super) source: i128,
    pub(super) actual: i128,
    pub(super) group: Option<String>,
}

pub(super) fn automatic_redis(rule: &TimeField) -> bool {
    rule.clock_group
        .as_deref()
        .is_some_and(|group| group.starts_with(AUTOMATIC_REDIS_GROUP_PREFIX))
}

/// Source chooses JSON-scalar or raw-text encoding before formats are applied.
/// Exact values need no clocks; valid timestamps still contribute copy checks.
pub(super) fn compare_wire_format(
    source: &[u8],
    actual: &[u8],
    rule: &TimeField,
    anchor: crate::primary_protocol::assertion::RequestTimes,
) -> Result<Option<ComparedTime>> {
    ensure!(
        automatic_redis(rule),
        "wire-format time comparison requires an automatic Redis declaration"
    );
    let Some(scalar) = crate::value_contract::redis_scalar::decode(source)? else {
        ensure!(source == actual, "unrecognized Redis time bytes changed");
        return Ok(None);
    };
    let target = scalar.target(actual)?;
    if source == actual || scalar.logical == target {
        return Ok(timestamp(&scalar.logical, rule)
            .ok()
            .map(|source| compared_pair(source, source, rule)));
    }
    compare(&scalar.logical, &target, rule, anchor).map(Some)
}

pub(super) fn offset(rule: &TimeField) -> Result<FixedOffset> {
    // Both values use the same origin, so its offset cancels in the difference.
    let offset = rule.utc_offset.as_deref().unwrap_or("+00:00");
    ensure!(
        offset != "-00:00"
            && offset.len() == 6
            && matches!(offset.as_bytes()[0], b'+' | b'-')
            && offset.as_bytes()[3] == b':'
            && offset
                .bytes()
                .enumerate()
                .all(|(i, b)| matches!(i, 0 | 3) || b.is_ascii_digit()),
        "utc_offset must use explicit +/-HH:MM"
    );
    let parsed = DateTime::parse_from_rfc3339(&format!("2000-01-01T00:00:00{offset}"))?;
    ensure!(
        parsed.offset().local_minus_utc().abs() <= 14 * 3600,
        "utc_offset exceeds 14 hours"
    );
    Ok(*parsed.offset())
}

pub(super) fn compare(
    source: &Value,
    actual: &Value,
    rule: &TimeField,
    anchor: crate::primary_protocol::assertion::RequestTimes,
) -> Result<ComparedTime> {
    let format = core_format(rule.format);
    time::validate_representation(source, actual, format)?;
    let pair = (timestamp(source, rule)?, timestamp(actual, rule)?);
    config::tolerance(&rule.tolerance)?;
    let anchor = time::timestamp_clocks(source, actual, format, anchor);
    time::compare_timestamp_nanos(pair.0, pair.1, TimeMode::PreserveRelative, anchor)
        .map_err(|_| anyhow::anyhow!("request timestamp differs from its recorded relative time or is missing its request anchor"))?;
    Ok(compared_pair(pair.0, pair.1, rule))
}

fn core_format(format: Format) -> TimestampFormat {
    match format {
        Format::UnixSeconds => TimestampFormat::UnixSeconds,
        Format::UnixMilliseconds => TimestampFormat::UnixMilliseconds,
        Format::UnixMicroseconds => TimestampFormat::UnixMicroseconds,
        Format::Rfc3339 => TimestampFormat::Rfc3339,
        Format::Iso8601Naive => TimestampFormat::Iso8601Naive,
        Format::SqlDatetime => TimestampFormat::SqlDatetime,
        Format::AmzDate => TimestampFormat::AmzDate,
    }
}

fn compared_pair(source: i128, actual: i128, rule: &TimeField) -> ComparedTime {
    ComparedTime {
        source,
        actual,
        group: rule.clock_group.as_ref().map(|group| {
            if group.starts_with(AUTOMATIC_REDIS_GROUP_PREFIX) {
                // Compact command declarations describe only formats. Copies
                // share an internal scope by their normalized Source instant;
                // distinct Source instants retain independent relative shifts.
                format!("{AUTOMATIC_REDIS_GROUP_PREFIX}{source}")
            } else {
                group.clone()
            }
        }),
    }
}

pub(super) fn timestamp(value: &Value, rule: &TimeField) -> Result<i128> {
    rule.validate()?;
    let (format, utc_offset) = match rule.format {
        Format::Rfc3339 => {
            let parsed = DateTime::parse_from_rfc3339(
                value
                    .as_str()
                    .context("timestamp must be an RFC3339 string")?,
            )?;
            ensure!(
                parsed.nanosecond() < 1_000_000_000,
                "leap seconds are unsupported"
            );
            (TimestampFormat::Rfc3339, None)
        }
        Format::Iso8601Naive => (TimestampFormat::Iso8601Naive, Some(offset(rule)?)),
        Format::SqlDatetime => (TimestampFormat::SqlDatetime, Some(offset(rule)?)),
        Format::AmzDate => (TimestampFormat::AmzDate, None),
        format => {
            ensure!(value.is_number(), "timestamp must be numeric");
            let format = match format {
                Format::UnixSeconds => TimestampFormat::UnixSeconds,
                Format::UnixMilliseconds => TimestampFormat::UnixMilliseconds,
                Format::UnixMicroseconds => TimestampFormat::UnixMicroseconds,
                _ => unreachable!(),
            };
            (format, None)
        }
    };
    let nanos = time::parse_timestamp(value, format, utc_offset)?;
    ensure!(
        (-62_135_596_800_000_000_000..=253_402_300_799_999_999_999).contains(&nanos),
        "timestamp must be within years 1..9999"
    );
    Ok(nanos)
}

pub(super) fn validate_relationships(times: &[ComparedTime]) -> Result<()> {
    let mut groups: BTreeMap<Option<&str>, Vec<(i128, i128)>> = BTreeMap::new();
    for value in times {
        groups
            .entry(value.group.as_deref())
            .or_default()
            .push((value.source, value.actual));
    }
    for values in groups.values() {
        time::validate_relationships(values)
            .context("request time parameter relationship changed")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
