//! Exact request timestamp parsing and independently captured clock validation.
use super::*;
use crate::replay::assertion::time::{compare_timestamp_delta, date_nanos, numeric_nanos_scaled};
use chrono::{FixedOffset, NaiveDateTime, Timelike};
use config::{RequestTimestampFormat as Format, TimeField};

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
) -> Result<(i128, i128)> {
    ensure!(
        source.is_i64() == actual.is_i64() && source.is_u64() == actual.is_u64(),
        "timestamp numeric category changed"
    );
    let pair = (timestamp(source, rule)?, timestamp(actual, rule)?);
    config::tolerance(&rule.tolerance)?;
    compare_timestamp_delta(pair.0, pair.1, anchor)
        .map_err(|_| anyhow::anyhow!("request timestamp differs from its recorded relative time or is missing its request anchor"))?;
    Ok(pair)
}

pub(super) fn timestamp(value: &Value, rule: &TimeField) -> Result<i128> {
    rule.validate()?;
    let nanos = match rule.format {
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
            date_nanos(parsed.with_timezone(&Utc))
        }
        Format::Iso8601Naive => {
            let text = value
                .as_str()
                .context("timestamp must be a naive ISO8601 string")?;
            ensure!(
                (19..=29).contains(&text.len())
                    && text.as_bytes().get(10) == Some(&b'T')
                    && (text.len() == 19
                        || text.as_bytes()[19] == b'.'
                            && text.len() > 20
                            && text.as_bytes()[20..].iter().all(u8::is_ascii_digit)),
                "naive ISO8601 requires YYYY-MM-DDTHH:MM:SS[.fraction] without a timezone"
            );
            let parsed = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f")?;
            ensure!(
                parsed.nanosecond() < 1_000_000_000,
                "leap seconds are unsupported"
            );
            let parsed = parsed
                .and_local_timezone(offset(rule)?)
                .single()
                .context("invalid naive timestamp")?;
            date_nanos(parsed.with_timezone(&Utc))
        }
        format => {
            ensure!(value.is_number(), "timestamp must be numeric");
            let scale = match format {
                Format::UnixSeconds => 9,
                Format::UnixMilliseconds => 6,
                Format::UnixMicroseconds => 3,
                _ => unreachable!(),
            };
            numeric_nanos_scaled(value, scale, 1).context("invalid numeric timestamp")?
        }
    };
    ensure!(
        (-62_135_596_800_000_000_000..=253_402_300_799_999_999_999).contains(&nanos),
        "timestamp must be within years 1..9999"
    );
    Ok(nanos)
}

pub(super) fn validate_relationships(times: &[(i128, i128)]) -> Result<()> {
    for (i, a) in times.iter().enumerate() {
        for b in &times[i + 1..] {
            ensure!(
                if a.0 == b.0 {
                    a.1 == b.1
                } else {
                    (a.1 - a.0).abs_diff(b.1 - b.0) <= 1000
                },
                "request time parameter relationship changed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
