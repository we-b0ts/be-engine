//! Adapt response time policy and diagnostics to the shared pure time contracts.
#[cfg(test)]
use chrono::DateTime;
use serde_json::Value;

use super::model::ResponseDifferenceKind;
use crate::policy::runtime::{
    ResponseDurationUnit, ResponseTimeRule, ResponseTimestampFormat, ResponseTimestampMode,
};
use crate::value_contract::time::{self, DurationUnit, TimeError, TimeMode, TimestampFormat};

pub(crate) use crate::value_contract::time::ClockPair as RequestTimes;

pub(crate) fn compare(
    rule: ResponseTimeRule,
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    validate_inputs(expected, actual, times)?;
    if let ResponseTimeRule::Timestamp { format, .. } = rule {
        time::validate_representation(expected, actual, timestamp_format(format))
            .map_err(difference)?;
    }
    match rule {
        ResponseTimeRule::Timestamp { format, mode } => time::compare_timestamp_nanos(
            timestamp_nanos(expected, format)?,
            timestamp_nanos(actual, format)?,
            match mode {
                ResponseTimestampMode::RequestWindow => TimeMode::RequestWindow,
                ResponseTimestampMode::PreserveRelative => TimeMode::PreserveRelative,
            },
            time::timestamp_clocks(expected, actual, timestamp_format(format), times),
        ),
        ResponseTimeRule::Duration { unit } => time::compare_duration_nanos(
            numeric_nanos(expected, unit).ok_or(ResponseDifferenceKind::TimeFieldInvalid)?,
            numeric_nanos(actual, unit).ok_or(ResponseDifferenceKind::TimeFieldInvalid)?,
            times,
        ),
    }
    .map_err(difference)
}

pub(super) fn compare_preserved_timestamp(
    format: ResponseTimestampFormat,
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    validate_inputs(expected, actual, times)?;
    time::validate_representation(expected, actual, timestamp_format(format))
        .map_err(difference)?;
    time::compare_timestamp_nanos(
        timestamp_nanos(expected, format)?,
        timestamp_nanos(actual, format)?,
        TimeMode::PreserveRelative,
        time::timestamp_clocks(expected, actual, timestamp_format(format), times),
    )
    .map_err(difference)
}

fn validate_inputs(
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    if !(expected.is_number() && actual.is_number() || expected.is_string() && actual.is_string()) {
        return Err(ResponseDifferenceKind::TimeFieldInvalid);
    }
    times.require().map(|_| ()).map_err(difference)
}

fn difference(error: TimeError) -> ResponseDifferenceKind {
    match error {
        TimeError::ReferenceMissing => ResponseDifferenceKind::TimeReferenceMissing,
        TimeError::OutsideWindow => ResponseDifferenceKind::TimestampOutsideRequestWindow,
        TimeError::DeltaMismatch => ResponseDifferenceKind::DurationDeltaMismatch,
        _ => ResponseDifferenceKind::TimeFieldInvalid,
    }
}

fn timestamp_nanos(
    value: &Value,
    format: ResponseTimestampFormat,
) -> Result<i128, ResponseDifferenceKind> {
    time::parse_timestamp(value, timestamp_format(format), None).map_err(difference)
}

fn timestamp_format(format: ResponseTimestampFormat) -> TimestampFormat {
    match format {
        ResponseTimestampFormat::UnixSeconds => TimestampFormat::UnixSeconds,
        ResponseTimestampFormat::UnixMilliseconds => TimestampFormat::UnixMilliseconds,
        ResponseTimestampFormat::Rfc3339 => TimestampFormat::Rfc3339,
        ResponseTimestampFormat::AmzDate => TimestampFormat::AmzDate,
    }
}

fn numeric_nanos(value: &Value, unit: ResponseDurationUnit) -> Option<i128> {
    let unit = match unit {
        ResponseDurationUnit::Seconds => DurationUnit::Seconds,
        ResponseDurationUnit::Milliseconds => DurationUnit::Milliseconds,
        ResponseDurationUnit::Minutes => DurationUnit::Minutes,
        ResponseDurationUnit::Hours => DurationUnit::Hours,
    };
    time::parse_duration(value, unit).ok()
}

#[cfg(test)]
mod tests;
