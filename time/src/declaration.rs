//! Temporal representations and their exact parsing contracts.
use crate::TimeError;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use traffic_policy::ValueScope as ClockScope;
mod automatic;
pub use automatic::{recognize_timestamp, timestamp_format};

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

/// Automatic groups carry no authored cross-field clock relationship.
pub fn is_schema_clock_group(group: &str) -> bool {
    group.strip_prefix("schema.").is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn same_type(source: &Value, target: &Value) -> bool {
    std::mem::discriminant(source) == std::mem::discriminant(target)
        && (!source.is_number() || crate::validate_numeric_category(source, target).is_ok())
}

pub fn core_format(format: TimestampFormat) -> Result<crate::TimestampFormat, TimeError> {
    Ok(match format {
        TimestampFormat::UnixSeconds => crate::TimestampFormat::UnixSeconds,
        TimestampFormat::UnixMilliseconds => crate::TimestampFormat::UnixMilliseconds,
        TimestampFormat::UnixMicroseconds => crate::TimestampFormat::UnixMicroseconds,
        TimestampFormat::Rfc3339 => crate::TimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => crate::TimestampFormat::AmzDate,
        TimestampFormat::Iso8601Naive => crate::TimestampFormat::Iso8601Naive,
        TimestampFormat::SqlDatetime => crate::TimestampFormat::SqlDatetime,
        TimestampFormat::CalendarDate => return Err(TimeError::InvalidValue),
    })
}

pub fn parse_time_pair(
    source: &Value,
    target: &Value,
    config: &TimeContract,
) -> Result<(i128, i128), TimeError> {
    if !same_type(source, target) {
        return Err(TimeError::NumericCategoryChanged);
    }
    if config.format != TimestampFormat::CalendarDate {
        crate::validate_representation(source, target, core_format(config.format)?)?;
    }
    Ok((
        parse_time_value(source, config)?,
        parse_time_value(target, config)?,
    ))
}

pub fn parse_time_value(value: &Value, config: &TimeContract) -> Result<i128, TimeError> {
    if matches!(
        config.format,
        TimestampFormat::UnixSeconds
            | TimestampFormat::UnixMilliseconds
            | TimestampFormat::UnixMicroseconds
    ) && !value.is_number()
    {
        return Err(TimeError::InvalidValue);
    }
    let offset = config.offset().map_err(|_| TimeError::InvalidValue)?;
    if config.format == TimestampFormat::CalendarDate {
        use chrono::Datelike;
        offset.ok_or(TimeError::InvalidValue)?;
        return Ok(i128::from(
            crate::calendar::parse(value)?.num_days_from_ce(),
        ));
    }
    crate::parse_timestamp(value, core_format(config.format)?, offset)
}
