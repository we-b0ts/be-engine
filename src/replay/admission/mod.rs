//! Application admission contexts use the shared finite Replay lifecycle.
pub(crate) mod request;
mod waiting;
pub(crate) use traffic_replay::{
    Barrier, ClaimKind, ClaimTicket, DeliveryGuard, Finish, Lifecycle, RequestOrder, WaitOutcome,
};
pub(crate) use waiting::RequestAdmission;
