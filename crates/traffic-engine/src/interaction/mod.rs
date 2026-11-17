//! Connection-scoped input transcripts, protocol observations and bounded lifetimes.

pub(crate) mod artifact;
pub(crate) use traffic_protocol_http::interaction::websocket_transport;
pub use traffic_protocol_http::interaction::{
    lifecycle, model, observation, policy, socketio, stream,
};
mod ownership;
pub mod private;
pub mod replay;
