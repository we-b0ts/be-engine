//! Native HTTP stream and Socket.IO framing, transcripts and peer observations.
//! Recording and Replay hosts retain I/O scheduling, authorization and persistence.
pub mod client;
mod heartbeat;
pub mod lifecycle;
pub mod model;
pub mod observation;
pub mod policy;
pub mod sessions;
pub mod socketio;
pub mod stream;
pub mod verification;
pub mod websocket_transport;
