//! Native timestamp admission keeps scalar adapters separate from JSON scopes.
use super::*;

pub fn validate_time(time: &NativeTime) -> Result<()> {
    ensure!(
        time.clock_scope.is_shared(),
        "scoped clocks require a JSON value contract or a MySQL JSON time field"
    );
    validate(time)
}

pub fn validate_json_time(time: &NativeTime, pointer: &str) -> Result<()> {
    validate(time)?;
    time.clock_scope.validate(pointer)?;
    ensure!(
        !matches!(time.clock_scope, crate::ClockScope::Entity { .. }),
        "entity clock_scope requires an SSE identity contract"
    );
    Ok(())
}

fn validate(time: &NativeTime) -> Result<()> {
    ensure!(
        time.format != TimestampFormat::CalendarDate,
        "calendar_date requires a value codec contract, including explicit delivery.rebase_time for read-state translation"
    );
    ensure!(
        matches!(
            time.anchor,
            crate::TimeAnchor::Observation | crate::TimeAnchor::DependencyRequestStart
        ),
        "time contracts require the corresponding comparison event"
    );
    ensure!(
        match time.format {
            TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => {
                time.relation == crate::TimeRelation::PreserveOffset || time.utc_offset.is_some()
            }
            _ => time.utc_offset.is_none(),
        },
        "naive request_window times require UTC offset; relative times need none; other time formats forbid it"
    );
    if let Some(value) = &time.utc_offset {
        offset(value)?;
    }
    if let Some(group) = &time.clock_group {
        identifier(group, "clock_group")?;
    }
    Ok(())
}
