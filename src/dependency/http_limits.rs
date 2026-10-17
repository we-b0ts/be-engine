//! Size budgets for complete HTTP bodies and their immutable JSON envelopes.

pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BASE64_BODY_BYTES: usize = MAX_BODY_BYTES.div_ceil(3) * 4;
const METADATA_BYTES: usize = 1024 * 1024;
// A response witness also carries the original request body.
pub(crate) const MAX_WITNESS_BYTES: usize = 2 * MAX_BASE64_BODY_BYTES + METADATA_BYTES;
// Recorded UTF-8 captures can use six JSON bytes per original control byte.
pub(crate) const MAX_RECORD_BYTES: usize = 12 * MAX_BODY_BYTES + METADATA_BYTES;
