//! Civil-day arithmetic. A date is never treated as a midnight timestamp:
//! preserving its day distance requires both independent local request dates.
use super::{ClockPair, TimeError, TimeMode};
use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, TimeDelta, Utc};
use serde_json::Value;

pub fn parse(value: &Value) -> Result<NaiveDate, TimeError> {
    let text = value.as_str().ok_or(TimeError::InvalidValue)?;
    if text.len() != 10
        || !text.bytes().enumerate().all(|(i, byte)| match i {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
    {
        return Err(TimeError::InvalidValue);
    }
    let date = NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| TimeError::InvalidValue)?;
    if !(1..=9999).contains(&date.year()) {
        return Err(TimeError::InvalidValue);
    }
    Ok(date)
}

fn local_date(clock: DateTime<Utc>, offset: FixedOffset) -> Result<NaiveDate, TimeError> {
    clock
        .naive_utc()
        .checked_add_signed(TimeDelta::seconds(i64::from(offset.local_minus_utc())))
        .map(|value| value.date())
        .ok_or(TimeError::InvalidValue)
}

pub fn compare(
    source: &Value,
    target: &Value,
    offset: FixedOffset,
    mode: TimeMode,
    clocks: ClockPair,
) -> Result<(i128, i128), TimeError> {
    let source = parse(source)?;
    let target = parse(target)?;
    let (source_anchor, target_anchor) = clocks.require()?;
    let source_days = source.signed_duration_since(local_date(source_anchor, offset)?);
    let target_days = target.signed_duration_since(local_date(target_anchor, offset)?);
    match mode {
        TimeMode::PreserveRelative if source_days != target_days => {
            return Err(TimeError::CalendarDayMismatch);
        }
        TimeMode::RequestWindow if !source_days.is_zero() || !target_days.is_zero() => {
            return Err(TimeError::CalendarDayMismatch);
        }
        _ => {}
    }
    Ok((
        i128::from(source.num_days_from_ce()),
        i128::from(target.num_days_from_ce()),
    ))
}

pub fn rebase(value: &Value, offset: FixedOffset, clocks: ClockPair) -> Result<Value, TimeError> {
    let date = parse(value)?;
    let (source, target) = clocks.require()?;
    let delta = local_date(target, offset)?.signed_duration_since(local_date(source, offset)?);
    let result = date
        .checked_add_signed(delta)
        .ok_or(TimeError::InvalidValue)?;
    if !(1..=9999).contains(&result.year()) {
        return Err(TimeError::InvalidValue);
    }
    Ok(result.format("%Y-%m-%d").to_string().into())
}

#[cfg(test)]
mod tests;
