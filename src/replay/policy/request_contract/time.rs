//! Exact request timestamp parsing and independently captured clock validation.
use super::*;
use crate::value_contract::time::{self, TimeMode, TimestampFormat};
use chrono::{FixedOffset, Timelike};
use config::{RequestTimestampFormat as Format, TimeField};

/// A validated timestamp pair and its explicitly declared relationship scope.
#[derive(Debug, Clone)]
pub(super) struct ComparedTime {
    pub(super) source: i128,
    pub(super) actual: i128,
    pub(super) group: Option<String>,
}

// JWT contracts retain their seconds interface; request times use integer nanoseconds.
pub(super) fn number(value: &Value) -> Result<f64> {
    let value = value.as_f64().context("timestamp must be numeric")?;
    ensure!(
        value.is_finite() && (-62_135_596_800.0..=253_402_300_799.0).contains(&value),
        "timestamp must be finite Unix seconds within years 1..9999"
    );
    Ok(value)
}

pub(super) fn offset(rule: &TimeField) -> Result<FixedOffset> {
    let offset = rule
        .utc_offset
        .as_deref()
        .context("iso8601_naive requires a source-proven utc_offset")?;
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
    anchor: crate::replay::assertion::RequestTimes,
) -> Result<ComparedTime> {
    time::validate_numeric_category(source, actual)?;
    let pair = (timestamp(source, rule)?, timestamp(actual, rule)?);
    config::tolerance(&rule.tolerance)?;
    time::compare_timestamp_nanos(pair.0, pair.1, TimeMode::PreserveRelative, anchor)
        .map_err(|_| anyhow::anyhow!("request timestamp differs from its recorded relative time or is missing its request anchor"))?;
    Ok(ComparedTime {
        source: pair.0,
        actual: pair.1,
        group: rule.clock_group.clone(),
    })
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
