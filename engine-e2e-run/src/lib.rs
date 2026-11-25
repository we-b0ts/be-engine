//! Managed E2E execution, Target runtime isolation and evidence publication.
pub mod build_info;
pub mod e2e_run;
pub mod execution_identity;
pub mod jwt_evidence;
pub mod platform;
pub use e2e_run::*;
pub use execution::{CleanupFuture, ExecutionDriver, ExecutionFuture, execute};
pub use target_container::TargetImage;

mod active_artifact;
mod active_progress;
mod admin_source;
mod admin_startup;
mod assertion_publication;
mod batch_evidence;
mod batch_planning;
mod batch_publication;
mod branch;
mod case_progress;
mod case_run;
mod case_selection;
mod case_sequence;
mod config;
mod delivery;
mod diagnostic_report;
mod dirty_evidence;
mod event_session;
mod evidence;
mod evidence_admission;
mod execute;
mod execution;
mod execution_failure;
mod failure_limit;
mod final_evidence;
mod focused_batch;
mod implementer_execution;
mod interrupted_evidence;
mod model;
mod primary_driver;
mod progress;
mod project_validation;
mod replay_publication;
mod replay_timer;
mod request_feedback;
mod request_view;
mod result;
mod run_config;
mod runtime;
mod source_response;
mod startup_inputs;
mod store;
mod support;
mod target_container;
mod target_stop;
#[cfg(test)]
pub(crate) mod test_session;
mod workflow_evidence;

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
