//! Stable Case membership for prepared native inventories.
use super::Postings;
use crate::ReplaySource;
use std::sync::Arc;

/// Membership is appended alongside protocol registration and freezes only the
/// changed Cases. Payload release and a new active Case never rebuild this map.
#[derive(Debug, Default)]
pub struct CaseMembership {
    positions: Postings<String>,
}

impl CaseMembership {
    pub fn register(&mut self, source: ReplaySource, case: Option<&str>, index: usize) {
        if source == ReplaySource::Case
            && let Some(case) = case
        {
            self.positions.register(case.to_owned(), index);
        }
    }

    pub fn seal(&mut self) {
        self.positions.seal();
    }

    pub fn for_case(&self, case: &str) -> Arc<[usize]> {
        self.positions.lookup(&case.to_owned())
    }
}
