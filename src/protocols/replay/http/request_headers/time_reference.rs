//! Resolve dependency-local clocks without using primary API or current time.
use super::*;
use chrono::DateTime;

pub(crate) fn source(record: &RecordedHttpExchange) -> Option<DateTime<Utc>> {
    record.native.source_started_at()
}

#[cfg(test)]
mod tests;
