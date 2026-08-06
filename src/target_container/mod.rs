mod build;
mod model;
mod preflight;
mod runtime;

use crate::TRAFFIC_PROCESS_USER;

pub(crate) use build::{build_image, image_tag};
pub use model::{TargetContainerChecks, TargetContainerPreflightResult, TargetImage};
pub(crate) use model::{TargetContainerConfig, TargetStartOptions};
pub(crate) use preflight::run_preflight;
pub(crate) use runtime::{
    bounded_logs, create_anchor, force_remove_runtime, is_running, prepare_boot_dir, runtime_name,
    start_target, stop_target, verify_config_mount, verify_listen_address,
    verify_required_environment, verify_target_identity,
};

pub(crate) const TARGET_DOCKERFILE_RELATIVE: &str = ".traffic-e2e/Dockerfile.e2e";
pub(crate) const TARGET_CONFIG_DIR: &str = "/traffic-e2e/config";
pub(crate) const TARGET_CONFIG_ENV: &str = "TRAFFIC_E2E_CONFIG_DIR";
pub(crate) const TARGET_PORT_ENV: &str = "TRAFFIC_E2E_TARGET_PORT";
pub(crate) const TARGET_REPLAY_CA_PATH: &str = "/traffic-e2e/trust/replay-ca.pem";
pub(crate) const TARGET_REPLAY_CA_ENV: &str = "TRAFFIC_E2E_REPLAY_CA_CERT_PATH";
pub(crate) const TARGET_USER: &str = TRAFFIC_PROCESS_USER;

const TARGET_BUILDER_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-builder:1.97.1@sha256:99663c03c7da6d638f9bef5d84d923840e2069e3f32067851b43ea7abf3f0004";
const TARGET_RUNTIME_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-rust-runtime:0.0.1@sha256:63072803f35282f2134f08779bd1652e51c4ff30ba08728716b616ef96b3dc80";

const NETWORK_ANCHOR_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-network-anchor:0.0.1@sha256:095f39e3b242e744ec8f7d85e732bb663af8a4a02bdef0d7a216d2e66e365a62";
const PROBE_IMAGE: &str = "registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107";
