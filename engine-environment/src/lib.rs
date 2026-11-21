//! Repository layout, sealed Source snapshots and managed startup inputs.
pub mod command_output;
pub mod engine_binary;
pub mod internal_runtime;
pub mod repository;
pub mod runtime_output;
pub mod source_snapshot;
pub mod startup;
pub mod tcp_listener;

pub use source_snapshot::{SourceImage, SourceProviderEvidence};
#[cfg(test)]
use traffic_engine::{
    DEFAULT_HTTP_BACKEND_PORT, DEFAULT_HTTP_GATEWAY_PORT, RepositoryConfigInitOptions,
    initialize_repository_config,
};

pub const TRAFFIC_PROCESS_UID: u32 = 998;
pub const TRAFFIC_PROCESS_GID: u32 = 998;
pub const TRAFFIC_PROCESS_USER: &str = "998:998";
