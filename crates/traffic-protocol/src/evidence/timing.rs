//! Native record clocks used by the framework's input schedule.
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy)]
pub enum SourceTiming {
    Unsupported,
    Control,
    Notification,
    Request {
        started_at: Option<DateTime<Utc>>,
        completed_at: Option<DateTime<Utc>>,
    },
}
