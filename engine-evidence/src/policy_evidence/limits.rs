//! Whole-session evidence budgets, shared by capture and catalog publication.

// A focused API can contain 70-100 Cases. Both Source and Target observations,
// plus every visited candidate association, share these budgets. A 15-Case
// Socket.IO run with a 4,096-event disconnect tail needed 276,365 observations.
pub(super) const MAX_OBSERVATIONS: usize = 393_216;
pub(super) const MAX_ASSOCIATIONS: usize = 1_048_576;

// Keep publication/read capacity aligned with the larger observation inventory.
// Payloads remain in authenticated Source references or sealed segments;
// this bound applies only to the private observation directory's metadata.
pub(super) const MAX_CATALOG_BYTES: u64 = 768 * 1024 * 1024;
