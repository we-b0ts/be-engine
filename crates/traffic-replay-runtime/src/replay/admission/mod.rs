//! Application admission contexts use the shared finite Replay lifecycle.
pub(crate) mod request;
mod waiting;
pub(crate) use traffic_replay::{Barrier, DeliveryGuard, Finish};
pub(crate) use waiting::RequestAdmission;
