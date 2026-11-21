//! Public application API shared by the three CLI entrypoints.
pub use traffic_e2e_app::*;

/// Version displayed by the installed CLI entrypoints.
pub const BINARY_VERSION: &str = env!("TRAFFIC_E2E_BUILD_VERSION");
