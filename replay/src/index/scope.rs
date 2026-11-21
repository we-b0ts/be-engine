//! Ownership partitions used by every prepared candidate index.
use crate::ReplaySource;

/// Startup and Process share matching permissions; their real ownership remains
/// on each exchange and is checked independently for startup/lane admission.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScopePartition {
    Case(Option<String>),
    Run,
    Shared,
}

impl ScopePartition {
    pub fn new(source: ReplaySource, case: Option<&str>) -> Self {
        if source.is_run_owned() {
            Self::Run
        } else {
            Self::Case(case.map(str::to_owned))
        }
    }
}
