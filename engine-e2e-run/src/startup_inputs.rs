use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct StartupMountEntry {
    pub path: PathBuf,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupMountList {
    pub snapshot_id: String,
    pub mounts: Vec<StartupMountEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupMountPresence {
    pub path: PathBuf,
    pub exists: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupMountChangeStatus {
    Added,
    Unchanged,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupMountChange {
    pub path: PathBuf,
    pub status: StartupMountChangeStatus,
    pub snapshot_id: String,
    pub writable: bool,
}

pub fn list_startup_mounts(target_root: &Path) -> Result<StartupMountList> {
    let (target_root, project) = load_project(target_root)?;
    let snapshot =
        crate::startup::load_startup_snapshot(&target_root, &project.project.target.startup)?;
    Ok(StartupMountList {
        snapshot_id: snapshot.snapshot_id().to_string(),
        mounts: snapshot
            .mounts()
            .iter()
            .map(|mount| StartupMountEntry {
                path: mount.path.clone(),
                writable: mount.writable,
            })
            .collect(),
    })
}

pub fn startup_mount_exists(target_root: &Path, path: &Path) -> Result<StartupMountPresence> {
    crate::startup::validate_mount_path(path)?;
    let mounts = list_startup_mounts(target_root)?;
    Ok(StartupMountPresence {
        path: path.to_path_buf(),
        exists: mounts.mounts.iter().any(|mount| mount.path == path),
    })
}

pub fn ensure_startup_mount(target_root: &Path, path: &Path) -> Result<StartupMountChange> {
    crate::startup::validate_mount_path(path)?;
    let (target_root, mut project) = load_project(target_root)?;
    let current = project.project.target.startup.clone();
    if current.mounts.iter().any(|mount| mount == path) {
        let snapshot = crate::startup::load_startup_snapshot(&target_root, &current)?;
        let mount = snapshot
            .mounts()
            .iter()
            .find(|mount| mount.path == path)
            .expect("validated snapshot contains configured mount");
        return Ok(StartupMountChange {
            path: path.to_path_buf(),
            status: StartupMountChangeStatus::Unchanged,
            snapshot_id: snapshot.snapshot_id().to_string(),
            writable: mount.writable,
        });
    }

    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(super::run_config::PROJECT_CONFIG_FILE);
    let original = fs::read(&config_path)
        .with_context(|| format!("failed to read project config {}", config_path.display()))?;
    let mut updated = current.clone();
    updated.mounts.push(path.to_path_buf());
    updated = crate::startup::normalized_config(updated)?;
    project.project.target.startup = updated;
    super::project_validation::validate_project_config(&project)?;
    let payload = render_project(&project)?;
    crate::config::edit::write_atomic(&config_path, &payload)?;

    let snapshot = match crate::startup::extend_startup_snapshot(&target_root, &current, path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if let Err(rollback) = crate::config::edit::write_atomic(&config_path, &original) {
                return Err(error.context(format!(
                    "startup mount capture failed and project config rollback also failed: {rollback:#}"
                )));
            }
            return Err(error.context("startup mount capture failed; project config was restored"));
        }
    };
    let writable = snapshot
        .writable_mounts
        .iter()
        .any(|configured| configured == path);
    Ok(StartupMountChange {
        path: path.to_path_buf(),
        status: StartupMountChangeStatus::Added,
        snapshot_id: snapshot.snapshot_id,
        writable,
    })
}

fn load_project(target_root: &Path) -> Result<(PathBuf, super::model::ProjectConfig)> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(super::run_config::PROJECT_CONFIG_FILE);
    let project = super::run_config::load_project_config(&target_root, &config_path)?;
    Ok((target_root, project))
}

fn render_project(project: &super::model::ProjectConfig) -> Result<Vec<u8>> {
    let mut payload = serde_yaml::to_string(project)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    Ok(payload)
}
