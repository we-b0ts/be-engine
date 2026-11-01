//! Source determines temporal representation independently of clock tolerance.
use super::{TimeError, TimestampFormat};
use serde_json::Value;

pub(crate) fn validate(
    source: &Value,
    target: &Value,
    format: TimestampFormat,
) -> Result<(), TimeError> {
    if matches!(
        format,
        TimestampFormat::UnixSeconds
            | TimestampFormat::UnixMilliseconds
            | TimestampFormat::UnixMicroseconds
    ) {
        return super::validate_numeric_category(source, target);
    }
    let (Some(source), Some(target)) = (source.as_str(), target.as_str()) else {
        return Err(TimeError::InvalidValue);
    };
    let same = source.len() == target.len()
        && source
            .bytes()
            .zip(target.bytes())
            .all(|(a, b)| (a.is_ascii_digit() && b.is_ascii_digit()) || a == b)
        && (format != TimestampFormat::Rfc3339 || zone(source) == zone(target));
    if !same {
        return Err(TimeError::RepresentationChanged);
    }
    Ok(())
}

fn zone(value: &str) -> Option<&str> {
    if value.ends_with(['Z', 'z']) {
        value.get(value.len().checked_sub(1)?..)
    } else {
        value.get(value.len().checked_sub(6)?..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clock_tolerance_does_not_change_fraction_width_or_zone_representation() {
        for (source, target, format) in [
            (
                "2026-01-01T01:02:03.123Z",
                "2027-01-01T01:02:03.123000Z",
                TimestampFormat::Rfc3339,
            ),
            (
                "2026-01-01T01:02:03Z",
                "2027-01-01T01:02:03+00:00",
                TimestampFormat::Rfc3339,
            ),
            (
                "2026-01-01T01:02:03+08:00",
                "2027-01-01T01:02:03+09:00",
                TimestampFormat::Rfc3339,
            ),
            (
                "2026-01-01T01:02:03.123",
                "2027-01-01T01:02:03",
                TimestampFormat::Iso8601Naive,
            ),
            (
                "2026-01-01 01:02:03",
                "2027-01-01 01:02:03.0",
                TimestampFormat::SqlDatetime,
            ),
        ] {
            assert_eq!(
                validate(&json!(source), &json!(target), format),
                Err(TimeError::RepresentationChanged)
            );
        }
        assert!(
            validate(
                &json!("2026-01-01T01:02:03.123+08:00"),
                &json!("2027-02-03T04:05:06.456+08:00"),
                TimestampFormat::Rfc3339
            )
            .is_ok()
        );
    }
}
