//! Whole-session evidence budgets, shared by capture and catalog publication.

// A focused API can contain 70-100 Cases. Both Source and independent Target
// observations, plus every visited candidate association, share these budgets.
// A genuine 70-Case run exceeded 116K observations and 288K association attempts;
// the old 64K/256K limits lost late requests even with segmented payload storage.
pub(super) const MAX_OBSERVATIONS: usize = 262_144;
pub(super) const MAX_ASSOCIATIONS: usize = 1_048_576;

// Keep publication/read capacity aligned with the larger observation inventory.
// Payloads remain in authenticated Source references or sealed segments;
// this bound applies only to the private observation directory's metadata.
pub(super) const MAX_CATALOG_BYTES: u64 = 512 * 1024 * 1024;
