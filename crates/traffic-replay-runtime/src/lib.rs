//! Replay session lifecycle and native connection execution over engine contracts.
use traffic_engine::*;
use traffic_engine::{
    dependency, dependency_index, interaction, policy_evidence, primary_protocol, recorder,
    recording_network, request_headers, tls, value_contract, value_extensions,
};
mod adapters;
mod replay;
pub use adapters::runtime::{
    run_mysql_replay, run_replay, run_replay_with_counters, run_replay_with_lifecycle,
    run_replay_with_providers,
};
pub use traffic_engine::{
    MysqlReplayConfig, ReplayAllowedUnusedHttpConfig, ReplayConfig, ReplayLifecycleConfig,
};

use traffic_engine::protocols::DependencyProviders;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use crate::adapters::http_test_support::{
        TestHttpReplayRuntime, snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
    };
    pub use traffic_engine::test_support::*;
}

#[cfg(test)]
use traffic_engine::config;
