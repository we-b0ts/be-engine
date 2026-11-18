//! Recorder settings and pure Source acquisition policy projection.
pub use traffic_engine_environment::{
    internal_runtime, repository, runtime_output, source_snapshot, startup,
};
pub use traffic_engine_policy::policy;
pub mod access_policy;
pub mod breeze;
pub mod config;
pub mod dns_mock;
mod interaction;
pub mod json_value;
pub mod mysql;
pub mod path_pattern;
pub mod protocol_contract;
mod protocols;
pub mod recording_api;
pub mod redis;
pub mod value_limits;
pub use config::*;
pub fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
fn installed_protocols() -> Vec<&'static str> {
    let mut providers =
        traffic_protocol::ProviderRegistry::<traffic_protocol::ProtocolId>::default();
    traffic_extensions::install_protocols(&mut providers, traffic_protocol::ProtocolId::new)
        .expect("unique installed protocols");
    providers
        .registrations()
        .iter()
        .map(|p| p.provider.name())
        .collect()
}
pub mod dependency;
mod recorder;
pub mod replay;
pub use mysql::operation::MysqlWriteOperation;
pub use traffic_model::DependencyExchangeOutcome;
pub mod http;
pub mod project;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
