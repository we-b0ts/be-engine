//! Connection-scoped input transcripts, protocol observations and bounded lifetimes.

pub mod lifecycle;
pub mod model;
pub mod observation;
mod ownership;
pub mod policy;
pub(crate) mod private;
pub(crate) mod replay;
pub mod socketio;
pub mod stream;
