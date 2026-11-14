//! Explicit Source-proven repeat and coalescing coverage.
use super::ClaimTicket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeClaimKind {
    ReusableSnapshot,
    StateObservation,
    ActivityRefresh,
    AppendStream,
}

/// Native repeat/coalescing operators own their explicit multi-slot accounting.
/// Ordinary finite exchanges must always carry a shared finite ticket.
#[derive(Debug, Clone)]
pub(super) enum Claim {
    Finite(ClaimTicket),
    Native(NativeClaimKind),
}
