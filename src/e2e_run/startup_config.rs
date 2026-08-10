use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::config::{
    CONFIG_VERSION, LEGACY_BOOT_CONFIG_VERSION, load_project_config, validate_project_config,
};
use super::model::ProjectConfig;
use super::{branch, store};

const PROJECT_CONFIG_FILE: &str = "project.yaml";

pub(crate) fn update_project_startup(
    target_root: &Path,
    startup: crate::startup::StartupConfig,
) -> Result<()> {
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(PROJECT_CONFIG_FILE);
    let startup = crate::startup::normalized_config(startup)?;
    let value: serde_yaml::Value = store::read_yaml(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let version = project_config_version(&value)?;
    let legacy = version == LEGACY_BOOT_CONFIG_VERSION;
    let mut config = if version == LEGACY_BOOT_CONFIG_VERSION {
        migrate_legacy_boot_config(value, startup)?
    } else {
        let mut config: ProjectConfig =
            serde_yaml::from_value(value).context("project configuration is invalid")?;
        config.target.startup = startup;
        config
    };
    config.version = CONFIG_VERSION;
    validate_project_config(&config)?;
    branch::validate_pr_base(target_root, &config.delivery.pr_base)?;
    let mut payload = serde_yaml::to_string(&config)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    let moved_runtime = legacy && migrate_legacy_runtime_root(target_root)?;
    if let Err(error) = crate::config::edit::write_atomic(&config_path, &payload) {
        if moved_runtime {
            let current = target_root.join(crate::internal_runtime::REPOSITORY_RELATIVE_ROOT);
            let legacy = target_root.join(".traffic-e2e/local/ai-forbidden");
            fs::rename(&current, &legacy).with_context(|| {
                format!(
                    "project update failed and runtime state could not be restored from {} to {}",
                    current.display(),
                    legacy.display()
                )
            })?;
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn resolve_startup_update_context(
    target_root: &Path,
) -> Result<(PathBuf, String, Option<crate::startup::StartupConfig>)> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    let config_path = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(PROJECT_CONFIG_FILE);
    let value: serde_yaml::Value = store::read_yaml(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    match project_config_version(&value)? {
        CONFIG_VERSION => {
            let config = load_project_config(&target_root, &config_path)?;
            Ok((
                target_root,
                config.source.container,
                Some(config.target.startup),
            ))
        }
        LEGACY_BOOT_CONFIG_VERSION => {
            let config =
                migrate_legacy_boot_config(value, crate::startup::StartupConfig::default())?;
            branch::validate_pr_base(&target_root, &config.delivery.pr_base)?;
            Ok((target_root, config.source.container, None))
        }
        version => bail!(
            "startup update supports project config versions {LEGACY_BOOT_CONFIG_VERSION} and {CONFIG_VERSION}, got {version}"
        ),
    }
}

fn project_config_version(value: &serde_yaml::Value) -> Result<u32> {
    let version = value
        .as_mapping()
        .and_then(|mapping| mapping.get(serde_yaml::Value::String("version".to_string())))
        .and_then(serde_yaml::Value::as_u64)
        .context("project configuration has no integer version")?;
    u32::try_from(version).context("project configuration version exceeds u32")
}

fn migrate_legacy_boot_config(
    mut value: serde_yaml::Value,
    startup: crate::startup::StartupConfig,
) -> Result<ProjectConfig> {
    let root = value
        .as_mapping_mut()
        .context("project configuration root must be a mapping")?;
    root.insert(
        serde_yaml::Value::String("version".to_string()),
        serde_yaml::to_value(CONFIG_VERSION)?,
    );
    let target = root
        .get_mut(serde_yaml::Value::String("target".to_string()))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .context("project configuration target must be a mapping")?;
    target.remove(serde_yaml::Value::String("boot_dir".to_string()));
    target.insert(
        serde_yaml::Value::String("startup".to_string()),
        serde_yaml::to_value(startup)?,
    );
    let state = root
        .get_mut(serde_yaml::Value::String("state".to_string()))
        .and_then(serde_yaml::Value::as_mapping_mut)
        .context("project configuration state must be a mapping")?;
    state.remove(serde_yaml::Value::String("ai_forbidden_root".to_string()));
    state.insert(
        serde_yaml::Value::String("runtime_root".to_string()),
        serde_yaml::Value::String(crate::internal_runtime::PROJECT_RELATIVE_ROOT.to_string()),
    );
    let config: ProjectConfig =
        serde_yaml::from_value(value).context("legacy project configuration cannot be migrated")?;
    validate_project_config(&config)?;
    Ok(config)
}

fn migrate_legacy_runtime_root(target_root: &Path) -> Result<bool> {
    let legacy = target_root.join(".traffic-e2e/local/ai-forbidden");
    let current = target_root.join(crate::internal_runtime::REPOSITORY_RELATIVE_ROOT);
    let metadata = match fs::symlink_metadata(&legacy) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", legacy.display()));
        }
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "legacy runtime root must be a directory and not a symlink: {}",
        legacy.display()
    );
    match fs::symlink_metadata(&current) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!(
            "cannot migrate runtime state because both {} and {} exist",
            legacy.display(),
            current.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", current.display()));
        }
    }
    fs::rename(&legacy, &current).with_context(|| {
        format!(
            "failed to migrate runtime state from {} to {}",
            legacy.display(),
            current.display()
        )
    })?;
    Ok(true)
}
