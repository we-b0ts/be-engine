use chrono::{DateTime, Utc};
use serde_json::Value;

use super::model::ResponseDifferenceKind;
use crate::replay::policy::{ResponseDurationUnit, ResponseTimeRule, ResponseTimestampFormat};

const NANOS_PER_SECOND: i128 = 1_000_000_000;
const TOLERANCE_NANOS: u128 = 5_000_000_000;

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::replay) struct RequestTimes {
    pub(in crate::replay) source: Option<DateTime<Utc>>,
    pub(in crate::replay) target: Option<DateTime<Utc>>,
}

pub(super) fn compare(
    rule: ResponseTimeRule,
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    let invalid = ResponseDifferenceKind::TimeFieldInvalid;
    if !(expected.is_number() && actual.is_number() || expected.is_string() && actual.is_string()) {
        return Err(invalid);
    }
    let (Some(source_time), Some(target_time)) = (times.source, times.target) else {
        return Err(ResponseDifferenceKind::TimeReferenceMissing);
    };
    match rule {
        ResponseTimeRule::Timestamp { format } => {
            let source = timestamp_nanos(expected, format).ok_or(invalid)?;
            let target = timestamp_nanos(actual, format).ok_or(invalid)?;
            if source.abs_diff(date_nanos(source_time)) > TOLERANCE_NANOS
                || target.abs_diff(date_nanos(target_time)) > TOLERANCE_NANOS
            {
                return Err(ResponseDifferenceKind::TimestampOutsideRequestWindow);
            }
        }
        ResponseTimeRule::Duration { unit } => {
            let source = numeric_nanos(expected, unit).ok_or(invalid)?;
            let target = numeric_nanos(actual, unit).ok_or(invalid)?;
            let duration_delta = target.checked_sub(source).ok_or(invalid)?;
            let request_delta = date_nanos(target_time) - date_nanos(source_time);
            if duration_delta.abs_diff(request_delta) > TOLERANCE_NANOS {
                return Err(ResponseDifferenceKind::DurationDeltaMismatch);
            }
        }
    }
    Ok(())
}

pub(super) fn compare_preserved_timestamp(
    format: ResponseTimestampFormat,
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    let invalid = ResponseDifferenceKind::TimeFieldInvalid;
    if !(expected.is_number() && actual.is_number() || expected.is_string() && actual.is_string()) {
        return Err(invalid);
    }
    let (Some(source_time), Some(target_time)) = (times.source, times.target) else {
        return Err(ResponseDifferenceKind::TimeReferenceMissing);
    };
    let source = timestamp_nanos(expected, format).ok_or(invalid)?;
    let target = timestamp_nanos(actual, format).ok_or(invalid)?;
    let timestamp_delta = target.checked_sub(source).ok_or(invalid)?;
    let request_delta = date_nanos(target_time) - date_nanos(source_time);
    if timestamp_delta.abs_diff(request_delta) > TOLERANCE_NANOS {
        return Err(ResponseDifferenceKind::DurationDeltaMismatch);
    }
    Ok(())
}

fn date_nanos(time: DateTime<Utc>) -> i128 {
    i128::from(time.timestamp()) * NANOS_PER_SECOND + i128::from(time.timestamp_subsec_nanos())
}

fn timestamp_nanos(value: &Value, format: ResponseTimestampFormat) -> Option<i128> {
    match format {
        ResponseTimestampFormat::UnixSeconds => numeric_nanos(value, ResponseDurationUnit::Seconds),
        ResponseTimestampFormat::UnixMilliseconds => {
            numeric_nanos(value, ResponseDurationUnit::Milliseconds)
        }
        ResponseTimestampFormat::Rfc3339 => DateTime::parse_from_rfc3339(value.as_str()?)
            .ok()
            .map(|time| date_nanos(time.with_timezone(&Utc))),
    }
}

/// Parse decimal numbers (including numeric strings and scientific notation)
/// to nanoseconds without floating-point subtraction. Round fractional
/// nanoseconds to the nearest nanosecond and reject arithmetic overflow.
fn numeric_nanos(value: &Value, unit: ResponseDurationUnit) -> Option<i128> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => return None,
    };
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (text.as_str(), 0),
    };
    let negative = mantissa.starts_with('-');
    let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (unsigned.contains('.') && fraction.is_empty())
    {
        return None;
    }
    let multiplier = match unit {
        ResponseDurationUnit::Minutes => 60,
        ResponseDurationUnit::Hours => 3600,
        _ => 1,
    };
    let digits = format!("{whole}{fraction}")
        .parse::<i128>()
        .ok()?
        .checked_mul(multiplier)?;
    let scale: i32 = match unit {
        ResponseDurationUnit::Milliseconds => 6,
        _ => 9,
    };
    let power = scale
        .checked_add(exponent)?
        .checked_sub(i32::try_from(fraction.len()).ok()?)?;
    let factor = 10_i128.checked_pow(power.unsigned_abs())?;
    let nanos = if power >= 0 {
        digits.checked_mul(factor)?
    } else {
        digits.checked_add(factor / 2)? / factor
    };
    Some(if negative { -nanos } else { nanos })
}

#[cfg(test)]
mod tests;
