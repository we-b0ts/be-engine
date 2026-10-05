//! Resolve dependency-local clocks without using primary API or current time.
use super::*;
use chrono::{DateTime, TimeDelta};

pub(in crate::replay) fn source(record: &RecordedHttpExchange) -> Option<DateTime<Utc>> {
    if let Some(request_started_at) = record.request_started_at {
        return Some(request_started_at);
    }
    let completed_at = record.timestamp?;
    let duration_ms = record.duration_ms.as_ref()?.as_u64()?;
    let duration = TimeDelta::try_milliseconds(i64::try_from(duration_ms).ok()?)?;
    completed_at.checked_sub_signed(duration)
}

#[cfg(test)]
mod tests;
