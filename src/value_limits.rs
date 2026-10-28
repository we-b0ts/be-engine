//! Shared byte ceiling for decoded values; business code owns its payload sizes.
/// Keep Redis carriers and their shared codecs/renderers on the same ceiling.
pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;
