use super::{branch, model::ProjectConfig, project_validation::validate_project_config};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use std::{fs, path::Path};
pub const CONFIG_VERSION: u32 = 18;
pub const DEFAULT_RUNTIME_ROOT: &str = crate::internal_runtime::PROJECT_RELATIVE_ROOT;
pub const PROJECT_CONFIG_FILE: &str = "project.yaml";
pub mod cache;
pub fn load_project_config(target_root: &Path, config_path: &Path) -> Result<ProjectConfig> {
    if let Some(config) = cache::document(config_path) {
        return Ok(config);
    }
    if !config_path.exists() {
        bail!(
            "{} is missing; from the target repository run `be-replay init \
             --source-pod <pod> --namespace <namespace>`",
            config_path.display()
        );
    }
    let config: ProjectConfig = read_yaml(config_path).with_context(|| {
        format!(
            "{} is incomplete or obsolete; in-place migration is not implemented, so preserve \
             the existing configuration and initialize a clean target repository",
            config_path.display()
        )
    })?;
    validate_project_config(&config).with_context(|| {
        format!(
            "{} is incomplete or obsolete; in-place migration is not implemented, so preserve \
             the existing configuration and initialize a clean target repository",
            config_path.display()
        )
    })?;
    branch::validate_pr_base(target_root, &config.project.delivery.pr_base)?;
    cache::insert_document(config_path.to_path_buf(), config.clone());
    Ok(config)
}

pub fn read_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file",
        path.display()
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read symlink {}",
        path.display()
    );
    let payload = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_slice(&payload)
        .with_context(|| format!("failed to parse YAML {}", path.display()))
}

pub fn load_target_startup(root: &Path) -> Result<crate::startup::StartupConfig> {
    let root = fs::canonicalize(root)?;
    let path = root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(PROJECT_CONFIG_FILE);
    Ok(load_project_config(&root, &path)?.project.target.startup)
}
