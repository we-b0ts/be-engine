use std::path::PathBuf;

use serde::Serialize;

#[derive(Debug, Clone)]
pub(crate) struct TargetContainerConfig {
    pub(crate) target_root: PathBuf,
    pub(crate) dockerfile: PathBuf,
    pub(crate) startup: crate::startup::StartupConfig,
    pub(crate) port: u16,
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
    pub(crate) runtime_outputs: &'a [crate::runtime_output::RuntimeOutputConfig],
    pub(crate) runtime_output_root: PathBuf,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) runtime_outputs: Vec<crate::RuntimeOutputLocation>,
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
pub(crate) struct TargetRuntimeState {
    pub(crate) running: bool,
    pub(crate) exit_code: i64,
    pub(crate) oom_killed: bool,
}
