//! Protocol-independent content decoding and value relationships.
pub mod codec;
pub mod comparison;
pub mod identity;
pub mod json;
pub mod path;
pub mod rule;
pub mod time;

/// Bound shared by content decoding, field projection and derived rendering.
pub const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;

pub mod compare;
pub mod hypothesis;
