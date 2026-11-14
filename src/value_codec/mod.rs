//! Shared content strategies plus the primary SSE carrier adapter.
pub(crate) mod sse;
pub(crate) use traffic_contract::codec::{CodecKind, CodecPlan, CodecView, DecodedValue};
#[cfg(test)]
use traffic_contract::codec::{Presence, ValueCodec};
#[cfg(test)]
pub(crate) use traffic_contract::codec::{measured_compiles, measured_decodes};
#[cfg(test)]
mod tests;
