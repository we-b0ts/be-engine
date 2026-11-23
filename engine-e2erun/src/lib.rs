//! Managed E2E execution, Target runtime isolation and evidence publication.
mod execution;
pub use execution::{CleanupFuture, ExecutionDriver, ExecutionFuture, execute};
pub mod build_info;
pub mod e2e_run;
pub mod execution_identity;
pub mod platform;
pub use e2e_run::*;
pub use target_container::TargetImage;
mod config;
mod replay_timer;
mod target_container;

use case_group::CaseGroupEnsureResult;
#[cfg(test)]
use config::AppConfig;
use network_probe::PreflightProbeKind;
#[cfg(test)]
use policy::runtime::ResponseBodyCodec;
use policy::runtime::ResponseJwtRule;
#[cfg(test)]
use primary_protocol::assertion::ResponseGatewayProtocol;
use recording_api::RecordingApi;
use replay::ReplayEgressRejections;
use runtime_output::RuntimeOutputLocation;
use source_snapshot::{KubernetesSourceOptions, SourceSnapshotReport};
use startup::StartupSnapshotReport;
use traffic_engine_config::{json_value, recording_api};
use traffic_engine_environment::{
    TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID, TRAFFIC_PROCESS_USER, engine_binary,
    internal_runtime, repository, runtime_output, source_snapshot, startup, tcp_listener,
};
use traffic_engine_evidence::artifact_owner::ArtifactOwner;
use traffic_engine_evidence::{
    api_trigger, case_group, coordination, dependency, dependency_index, policy_evidence,
    request_headers, verification_progress,
};
use traffic_engine_replay::replay;
use traffic_engine_verification::{
    interaction, policy, primary_protocol, recorded_request, request_rules, value_contract,
};
use traffic_recording_model::network_probe;

mod protocols {
    pub use traffic_engine_evidence::protocols::*;
    pub use traffic_engine_replay::protocols::replay;
}

#[cfg(test)]
use traffic_engine_recording::test_support;

/// Immutable target image tag shared with repository initialization.
pub fn target_image_tag(root: &std::path::Path) -> anyhow::Result<String> {
    target_container::image_tag(root)
}
