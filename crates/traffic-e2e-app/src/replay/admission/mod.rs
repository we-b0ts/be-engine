//! Application admission contexts use the shared finite Replay lifecycle.
pub(crate) mod request;
mod waiting;
pub(crate) use traffic_replay::{Barrier, ClaimTicket, DeliveryGuard, Finish, RequestOrder};
pub(crate) use waiting::RequestAdmission;
