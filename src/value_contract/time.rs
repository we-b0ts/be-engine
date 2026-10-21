//! Exact timestamp parsing and clock relations, independent of replay and configuration.
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, Timelike, Utc};
use serde_json::Value;
pub(crate) mod calendar;

pub(crate) const NANOS_PER_SECOND: i128 = 1_000_000_000;
const TOLERANCE_NANOS: u128 = 5_000_000_000;
const RELATIONSHIP_TOLERANCE_NANOS: u128 = 1000;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClockPair {
    pub(crate) source: Option<DateTime<Utc>>,
    pub(crate) target: Option<DateTime<Utc>>,
}

impl ClockPair {
    pub(crate) fn require(self) -> Result<(DateTime<Utc>, DateTime<Utc>), TimeError> {
        self.source
            .zip(self.target)
            .ok_or(TimeError::ReferenceMissing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeMode {
    RequestWindow,
    PreserveRelative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimestampFormat {
    UnixSeconds,
    UnixMilliseconds,
    UnixMicroseconds,
    Rfc3339,
    AmzDate,
    Iso8601Naive,
    SqlDatetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurationUnit {
    Seconds,
    Milliseconds,
    Microseconds,
    Minutes,
    Hours,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeError {
    InvalidValue,
    ReferenceMissing,
    OutsideWindow,
    DeltaMismatch,
    NumericCategoryChanged,
    RelationshipMismatch,
    CalendarDayMismatch,
}

impl std::fmt::Display for TimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidValue => "invalid time value",
            Self::ReferenceMissing => {
                "time relation requires independent source and target anchors"
            }
            Self::OutsideWindow => "timestamp is outside the fixed five-second anchor window",
            Self::DeltaMismatch => "time difference does not preserve the anchor difference",
            Self::NumericCategoryChanged => "timestamp numeric category changed",
            Self::RelationshipMismatch => "time parameter relationship changed",
            Self::CalendarDayMismatch => {
                "calendar date does not satisfy its local request-day relation"
            }
        })
    }
}

impl std::error::Error for TimeError {}

pub(crate) fn date_nanos(time: DateTime<Utc>) -> i128 {
    i128::from(time.timestamp()) * NANOS_PER_SECOND + i128::from(time.timestamp_subsec_nanos())
}

pub(crate) fn validate_request_window(value: i128, anchor: DateTime<Utc>) -> Result<(), TimeError> {
    if value.abs_diff(date_nanos(anchor)) > TOLERANCE_NANOS {
        return Err(TimeError::OutsideWindow);
    }
    Ok(())
}

pub(crate) fn compare_timestamp_nanos(
    source: i128,
    target: i128,
    mode: TimeMode,
    clocks: ClockPair,
) -> Result<(), TimeError> {
    let (source_anchor, target_anchor) = clocks.require()?;
    match mode {
        TimeMode::RequestWindow => {
            validate_request_window(source, source_anchor)?;
            validate_request_window(target, target_anchor)
        }
        TimeMode::PreserveRelative => compare_duration_nanos(source, target, clocks),
    }
}

pub(crate) fn compare_duration_nanos(
    source: i128,
    target: i128,
    clocks: ClockPair,
) -> Result<(), TimeError> {
    let (source_anchor, target_anchor) = clocks.require()?;
    let value_delta = target.checked_sub(source).ok_or(TimeError::InvalidValue)?;
    let anchor_delta = date_nanos(target_anchor) - date_nanos(source_anchor);
    if value_delta.abs_diff(anchor_delta) > TOLERANCE_NANOS {
        return Err(TimeError::DeltaMismatch);
    }
    Ok(())
}

/// A calendar date is a day-wide interval. Compare only the day changes that
/// can be proved from the independent request delta at that precision.
pub(crate) fn compare_calendar_dates(
    source: NaiveDate,
    target: NaiveDate,
    clocks: ClockPair,
) -> Result<(), TimeError> {
    const DAY: i128 = 86_400 * NANOS_PER_SECOND;
    let (source_anchor, target_anchor) = clocks.require()?;
    let delta = date_nanos(target_anchor) - date_nanos(source_anchor);
    let tolerance = TOLERANCE_NANOS as i128;
    let min_days = (delta - tolerance).div_euclid(DAY);
    let max_days = (delta + tolerance + DAY - 1).div_euclid(DAY);
    let days = i128::from(target.signed_duration_since(source).num_days());
    if !(min_days..=max_days).contains(&days) {
        return Err(TimeError::DeltaMismatch);
    }
    Ok(())
}

pub(crate) fn validate_numeric_category(source: &Value, target: &Value) -> Result<(), TimeError> {
    if source.is_i64() != target.is_i64() || source.is_u64() != target.is_u64() {
        return Err(TimeError::NumericCategoryChanged);
    }
    Ok(())
}

/// Equal source copies stay equal. Other fields must share a shift within one microsecond.
pub(crate) fn validate_relationships(times: &[(i128, i128)]) -> Result<(), TimeError> {
    for (index, source) in times.iter().enumerate() {
        for target in &times[index + 1..] {
            let valid = if source.0 == target.0 {
                source.1 == target.1
            } else {
                let source_shift = source
                    .1
                    .checked_sub(source.0)
                    .ok_or(TimeError::InvalidValue)?;
                let target_shift = target
                    .1
                    .checked_sub(target.0)
                    .ok_or(TimeError::InvalidValue)?;
                source_shift.abs_diff(target_shift) <= RELATIONSHIP_TOLERANCE_NANOS
            };
            if !valid {
                return Err(TimeError::RelationshipMismatch);
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_timestamp(
    value: &Value,
    format: TimestampFormat,
    utc_offset: Option<FixedOffset>,
) -> Result<i128, TimeError> {
    let invalid = TimeError::InvalidValue;
    match format {
        TimestampFormat::UnixSeconds => parse_duration(value, DurationUnit::Seconds),
        TimestampFormat::UnixMilliseconds => parse_duration(value, DurationUnit::Milliseconds),
        TimestampFormat::UnixMicroseconds => parse_duration(value, DurationUnit::Microseconds),
        TimestampFormat::Rfc3339 => DateTime::parse_from_rfc3339(value.as_str().ok_or(invalid)?)
            .map(|time| date_nanos(time.with_timezone(&Utc)))
            .map_err(|_| invalid),
        TimestampFormat::AmzDate => {
            let text = value.as_str().ok_or(invalid)?;
            if text.len() != 16
                || !text.bytes().enumerate().all(|(index, byte)| match index {
                    8 => byte == b'T',
                    15 => byte == b'Z',
                    _ => byte.is_ascii_digit(),
                })
            {
                return Err(invalid);
            }
            NaiveDateTime::parse_from_str(text, "%Y%m%dT%H%M%SZ")
                .map(|time| date_nanos(time.and_utc()))
                .map_err(|_| invalid)
        }
        TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => {
            let text = value.as_str().ok_or(invalid)?;
            if !(19..=29).contains(&text.len())
                || text.as_bytes().get(10)
                    != Some(
                        &(if format == TimestampFormat::SqlDatetime {
                            b' '
                        } else {
                            b'T'
                        }),
                    )
                || !(text.len() == 19
                    || text.as_bytes()[19] == b'.'
                        && text.len() > 20
                        && text.as_bytes()[20..].iter().all(u8::is_ascii_digit))
            {
                return Err(invalid);
            }
            let time = NaiveDateTime::parse_from_str(
                text,
                if format == TimestampFormat::SqlDatetime {
                    "%Y-%m-%d %H:%M:%S%.f"
                } else {
                    "%Y-%m-%dT%H:%M:%S%.f"
                },
            )
            .map_err(|_| invalid)?;
            if time.nanosecond() >= 1_000_000_000 {
                return Err(invalid);
            }
            time.and_local_timezone(utc_offset.ok_or(invalid)?)
                .single()
                .map(|time| date_nanos(time.with_timezone(&Utc)))
                .ok_or(invalid)
        }
    }
}

pub(crate) fn parse_duration(value: &Value, unit: DurationUnit) -> Result<i128, TimeError> {
    let (scale, multiplier) = match unit {
        DurationUnit::Seconds => (9, 1),
        DurationUnit::Milliseconds => (6, 1),
        DurationUnit::Microseconds => (3, 1),
        DurationUnit::Minutes => (9, 60),
        DurationUnit::Hours => (9, 3600),
    };
    numeric_nanos_scaled(value, scale, multiplier).ok_or(TimeError::InvalidValue)
}

/// Scale decimal numbers or numeric strings without floating-point subtraction.
/// Fractional nanoseconds round to the nearest nanosecond; overflow is rejected.
pub(crate) fn numeric_nanos_scaled(value: &Value, scale: i32, multiplier: i128) -> Option<i128> {
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
    let digits = format!("{whole}{fraction}")
        .parse::<i128>()
        .ok()?
        .checked_mul(multiplier)?;
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
