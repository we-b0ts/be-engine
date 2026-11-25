mod build;
mod model;
mod runtime;
mod runtime_outputs;
mod ssh_agent;
mod startup_mounts;

use crate::TRAFFIC_PROCESS_USER;

pub(crate) use build::{build_image, build_image_with_timer, image_tag};
pub use model::TargetImage;
pub(crate) use model::{TargetContainerConfig, TargetStartOptions};
pub(crate) use runtime::{
    capture_diagnostics, create_anchor, force_remove_runtime, runtime_name, start_target,
    stop_target, verify_listen_address, verify_runtime_mounts, verify_startup_environment,
    verify_target_identity,
};

pub(crate) const TARGET_DOCKERFILE_RELATIVE: &str = ".traffic-e2e/Dockerfile.target";
pub(crate) const TARGET_REPLAY_CA_PATH: &str = "/traffic-e2e/trust/replay-ca.pem";
pub(crate) const TARGET_USER: &str = TRAFFIC_PROCESS_USER;

const NETWORK_ANCHOR_IMAGE: &str = "be-engine-network-anchor:local";
