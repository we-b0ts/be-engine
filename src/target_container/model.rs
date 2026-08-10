use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone)]
pub(crate) struct TargetContainerConfig {
    pub(crate) target_root: PathBuf,
    pub(crate) dockerfile: PathBuf,
    pub(crate) startup: crate::startup::StartupConfig,
    pub(crate) port: u16,
    pub(crate) readiness_path: String,
    pub(crate) readiness_status: u16,
    pub(crate) startup_timeout: Duration,
    pub(crate) breeze_enabled: bool,
}

impl TargetContainerConfig {
    pub(crate) fn from_project(
        target_root: PathBuf,
        project: &crate::e2e_run::ResolvedProjectConfig,
    ) -> Self {
        Self {
            target_root,
            dockerfile: project.target_dockerfile.clone(),
            startup: project.target_startup.clone(),
            port: project.target_port,
            readiness_path: project.target_readiness_path.clone(),
            readiness_status: project.target_readiness_status,
            startup_timeout: project.target_startup_timeout,
            breeze_enabled: project.breeze_container.is_some(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetImage {
    pub tag: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetStartOptions<'a> {
    pub(crate) config: &'a TargetContainerConfig,
    pub(crate) image: &'a TargetImage,
    pub(crate) container_name: String,
    pub(crate) network_container: String,
    pub(crate) operation: &'static str,
    pub(crate) run_id: String,
    pub(crate) replay_ca_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TargetStartEvidence {
    pub(crate) status: &'static str,
    pub(crate) container_name: String,
    pub(crate) anchor_name: String,
    pub(crate) image_id: String,
    pub(crate) user: &'static str,
    pub(crate) startup_snapshot_id: String,
    pub(crate) startup_mounts: Vec<PathBuf>,
    pub(crate) port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replay_ca_cert: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TargetStopEvidence {
    pub(crate) status: &'static str,
    pub(crate) container_name: String,
    pub(crate) exit_code: i64,
    pub(crate) removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetContainerChecks {
    pub image_contract: bool,
    pub process_identity: bool,
    pub startup_snapshot: bool,
    pub startup_environment: bool,
    pub startup_mounts_read_only: bool,
    pub listen_all_interfaces: bool,
    pub readiness: bool,
    pub stdout_stderr_logging: bool,
    pub graceful_shutdown: bool,
    pub cleanup: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetContainerPreflightResult {
    pub status: &'static str,
    pub image: TargetImage,
    pub checks: TargetContainerChecks,
}
