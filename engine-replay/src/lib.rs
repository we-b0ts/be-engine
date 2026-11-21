//! Replay contracts, native inventory, report projections and asynchronous completion.
pub use replay::ReplayEgressRejections;
pub use tls::MitmCa;
pub use traffic_engine_config::config::*;
pub use traffic_engine_config::{
    config, json_value, mysql, path_pattern, protocol_contract, redis,
};
pub use traffic_engine_environment::{internal_runtime, repository, startup};
pub use traffic_engine_evidence::{
    api_trigger, attribution_defaults, coordination, dependency, dependency_index, policy_evidence,
    request_headers,
};
pub use traffic_engine_policy::policy;
pub use traffic_model::DependencyExchangeOutcome;
pub mod detection;
pub mod interaction;
pub mod protocols;
pub mod recorder;
pub mod replay;
pub mod tls;
pub mod value_contract;
pub mod value_extensions;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use traffic_engine_config::test_support::*;
    #[cfg(test)]
    pub use traffic_engine_recording::test_support::recording;
}
pub use traffic_model::{DependencyTermination, TerminationSide};
