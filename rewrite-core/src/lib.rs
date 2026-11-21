//! Protocol-independent persistent backend workflow state and transitions.
mod model;
mod transition;
mod types;
pub use model::{RewriteCasePatternIdentification, RewriteSliceState, RewriteState, WorkflowData};
pub use transition::{Attempt, AttemptCounts, ExecutionTransition, ExecutionUpdate};
pub use types::{RewriteApiProgress, RewriteApiStatus, RewriteAttemptDelta, RewritePhase};

mod store;
pub use store::{SnapshotStore, WorkflowLock, WorkflowLockState};

#[cfg(test)]
mod tests;
