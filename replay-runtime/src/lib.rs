//! Replay session lifecycle and native connection execution over engine contracts.
use traffic_engine_config::BackgroundDependencyRuleConfig;
use traffic_engine_evidence::{
    attribution_review, coordination, dependency, dependency_index, policy_evidence,
    request_headers,
};
use traffic_engine_replay::protocols::DependencyProviders;
use traffic_engine_replay::{MitmCa, protocols, recorder, tls, value_extensions};
use traffic_engine_verification::{interaction, policy, primary_protocol, value_contract};
use traffic_recording_model::recording_network;

#[cfg(test)]
use traffic_engine_config::{AppConfig, HttpGatewayRuleConfig, TrafficJsonlMode, config};
#[cfg(test)]
use traffic_engine_recording::{AppState, recorder::Recorder};
#[cfg(test)]
use traffic_engine_replay::protocols::replay::report::artifacts::read_global_dependency_page;
#[cfg(test)]
use traffic_model::DependencyExchangeOutcome;

mod adapters;
mod replay;

pub use adapters::runtime::{
    run_mysql_replay, run_replay, run_replay_with_counters, run_replay_with_lifecycle,
    run_replay_with_providers,
};
pub use traffic_engine_replay::protocols::replay::runtime::{
    MysqlReplayConfig, ReplayAllowedUnusedHttpConfig, ReplayConfig,
};
pub use traffic_engine_replay::replay::ReplayLifecycleConfig;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use crate::adapters::http_test_support::{
        TestHttpReplayRuntime, snapshot_http_replay, spawn_coordinator_http_replay, write_http_case,
    };
    pub use traffic_engine_recording::test_support::*;
}
