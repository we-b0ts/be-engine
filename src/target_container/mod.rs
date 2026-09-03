mod build;
mod model;
mod runtime;
mod runtime_outputs;
mod ssh_agent;
mod startup_mounts;

use crate::TRAFFIC_PROCESS_USER;
use crate::build_info::TARGET_RUNTIME_IMAGE;

pub(crate) use build::{build_image, image_tag};
pub use model::TargetImage;
pub(crate) use model::{TargetContainerConfig, TargetStartOptions};
pub(crate) use runtime::{
    capture_diagnostics, create_anchor, force_remove_runtime, runtime_name, start_target,
    stop_target, verify_listen_address, verify_runtime_mounts, verify_startup_environment,
    verify_target_identity,
};

pub(crate) const TARGET_DOCKERFILE_RELATIVE: &str = ".traffic-e2e/Dockerfile.e2e";
pub(crate) const TARGET_REPLAY_CA_PATH: &str = "/traffic-e2e/trust/replay-ca.pem";
pub(crate) const TARGET_USER: &str = TRAFFIC_PROCESS_USER;

const TARGET_BUILDER_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-builder:1.97.1@sha256:99663c03c7da6d638f9bef5d84d923840e2069e3f32067851b43ea7abf3f0004";

const NETWORK_ANCHOR_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62";
