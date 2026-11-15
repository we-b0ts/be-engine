//! Native observers bind trusted primary-driver feedback to dependency sessions.
use crate::interaction::replay::NativeEvent;
use anyhow::Result;
use chrono::{DateTime, Utc};

pub(crate) struct EventCapabilities {
    pub enabled: bool,
    pub events: bool,
    pub input_acks: bool,
}

pub(crate) trait NativeEventProjection: Send {
    fn request_begin(&mut self, case: &str, epoch: DateTime<Utc>) -> Result<()>;
    fn needs_native_events(&self, case: &str) -> bool;
    fn request_epoch(&self, case: &str) -> Option<DateTime<Utc>>;
    fn begin(&mut self, case: &str, epoch: DateTime<Utc>) -> EventCapabilities;
    fn input_acknowledged(&mut self, case: &str, epoch: DateTime<Utc>, sequence: u64)
    -> Result<()>;
    fn connected(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        namespace: &str,
        sid: Option<&str>,
    ) -> Result<()>;
    fn observe(&mut self, case: &str, epoch: DateTime<Utc>, event: &NativeEvent) -> Result<()>;
}
