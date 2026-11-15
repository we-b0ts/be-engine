//! Project-wide interpretation of standard textual time values.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimePolicy {
    pub default_utc_offset: String,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            default_utc_offset: "+08:00".into(),
        }
    }
}

impl TimePolicy {
    pub fn offset(&self) -> Result<chrono::FixedOffset> {
        super::TimeContract {
            format: super::TimestampFormat::CalendarDate,
            relation: super::TimeRelation::PreserveOffset,
            anchor: super::TimeAnchor::Observation,
            utc_offset: Some(self.default_utc_offset.clone()),
            clock_group: None,
            clock_scope: Default::default(),
        }
        .offset()?
        .context("time.default_utc_offset is required")
    }
}
