use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::config::{load_project_config, validate_project_config};
use super::model::MotanProjectConfig;

pub(crate) struct ProjectProtocolUpdate {
    pub(crate) path: PathBuf,
    pub(crate) recorder_config: PathBuf,
    pub(crate) payload: Vec<u8>,
    pub(crate) changed: bool,
}

pub(crate) fn render_motan_protocol_update(
    target_root: &Path,
    source_port: u16,
    gateway_port: u16,
    target_port: u16,
) -> Result<ProjectProtocolUpdate> {
    let path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join("project.yaml");
    let mut config = load_project_config(target_root, &path)?;
    let desired = MotanProjectConfig {
        source_port,
        gateway_port,
        target_port,
    };
    let changed = config.protocols.motan.as_ref() != Some(&desired);
    config.protocols.motan = Some(desired);
    validate_project_config(&config)?;
    let recorder_config = if config.recording.config.is_absolute() {
        config.recording.config.clone()
    } else {
        target_root.join(&config.recording.config)
    };
    let mut payload = serde_yaml::to_string(&config)
        .context("failed to serialize Motan project configuration")?
        .into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    Ok(ProjectProtocolUpdate {
        path,
        recorder_config,
        payload,
        changed,
    })
}
