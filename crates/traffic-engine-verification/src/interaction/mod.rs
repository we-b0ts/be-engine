//! Connection-scoped input transcripts, protocol observations and bounded lifetimes.

pub mod artifact;
pub use traffic_protocol_http::interaction::websocket_transport;
pub use traffic_protocol_http::interaction::{
    lifecycle, model, observation, policy, socketio, stream,
};
pub mod private;
pub mod replay;
