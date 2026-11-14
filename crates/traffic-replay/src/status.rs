//! Finite dependency status, independent of native messages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayExchangeStatus {
    #[default]
    Available,
    /// Unclaimed initialization traffic cannot be borrowed after the first primary input.
    StartupBlocked,
    Responding,
    AwaitingClientTermination,
    Consumed,
    /// A separately audited primary cancellation; recorded EOF was not delivered.
    Cancelled,
    Failed,
}

impl ReplayExchangeStatus {
    pub fn is_available(self) -> bool {
        self == Self::Available
    }

    pub fn is_covered(self) -> bool {
        self.is_consumed()
    }

    pub fn is_consumed(self) -> bool {
        self == Self::Consumed
    }
}
