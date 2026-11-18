//! Reusable implementation slots and explicit, fenced API assignments.
//! API dispatches, reviews and acceptance remain owned by `worker` and `review`.
mod feedback;
mod model;
mod planning;
mod replacement;

pub use feedback::{confirm, handoff, reassign, report};
pub use model::{
    ImplementerConfirmOptions, ImplementerDelivery, ImplementerDispatch, ImplementerHandoffOptions,
    ImplementerPool, ImplementerPoolView, ImplementerReassignOptions,
    ImplementerReplaceRuntimeOptions, ImplementerReportOptions, ImplementerSlotView,
    ImplementerTask,
};
pub(crate) use planning::{action, refresh, view};
pub use replacement::replace_runtime;

#[cfg(feature = "test-support")]
pub(crate) use planning::dispatch;
