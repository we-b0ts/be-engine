//! Application admission contexts use the shared finite Replay lifecycle.
pub(super) mod request;
mod waiting;
pub(super) use traffic_replay::{
    Barrier, ClaimKind, ClaimTicket, DeliveryGuard, Finish, Lifecycle, RequestOrder, WaitOutcome,
};
pub(crate) use waiting::RequestAdmission;
