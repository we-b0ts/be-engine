//! Shared initialization counts over native finite obligations.
use crate::{ReplayExchangeStatus, ReplaySource};

#[derive(Debug, Default, Clone, Copy)]
pub struct StartupCounts {
    pub required: usize,
    pub unstarted: usize,
}

impl StartupCounts {
    pub fn observe(
        &mut self,
        source: ReplaySource,
        status: &mut ReplayExchangeStatus,
        mandatory: bool,
        close: bool,
    ) {
        if source != ReplaySource::Startup || !mandatory {
            return;
        }
        self.required += 1;
        if status.is_available() {
            self.unstarted += 1;
            if close {
                *status = ReplayExchangeStatus::StartupBlocked;
            }
        }
    }
    pub fn merge(&mut self, other: Self) {
        self.required += other.required;
        self.unstarted += other.unstarted;
    }
}
