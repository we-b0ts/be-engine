//! Source ownership scopes shared by every dependency adapter.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySource {
    Startup,
    Process,
    Case,
    /// Original ambient input evidence has no proven business owner.
    Unattributed,
}

impl ReplaySource {
    pub fn is_run_owned(self) -> bool {
        matches!(self, Self::Startup | Self::Process)
    }
    pub fn is_run_level(self) -> bool {
        self != Self::Case
    }
    pub fn matches_scope(self, requested: Self) -> bool {
        self == requested || self.is_run_owned() && requested.is_run_owned()
    }
}
