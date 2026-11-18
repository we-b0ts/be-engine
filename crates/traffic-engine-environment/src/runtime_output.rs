use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_RUNTIME_OUTPUTS: usize = 16;
const MAX_ID_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOutputConfig {
    pub id: String,
    pub container_path: PathBuf,
    #[serde(default)]
    pub mode: RuntimeOutputMode,
    #[serde(default)]
    pub retention: RuntimeOutputRetention,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutputMode {
    #[default]
    ReadWrite,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutputRetention {
    #[default]
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOutputLocation {
    pub id: String,
    pub role: String,
    pub container_path: PathBuf,
    pub host_path: PathBuf,
    pub mode: String,
    pub retention: String,
}

pub fn validate_configs(
    configs: &[RuntimeOutputConfig],
    startup: &crate::startup::StartupConfig,
) -> Result<()> {
    ensure!(
        configs.len() <= MAX_RUNTIME_OUTPUTS,
        "target.runtime_outputs exceed the limit of {MAX_RUNTIME_OUTPUTS}"
    );
    let mut ids = BTreeSet::new();
    for config in configs {
        validate_id(&config.id)?;
        ensure!(
            ids.insert(config.id.as_str()),
            "target.runtime_outputs id {:?} is duplicated",
            config.id
        );
        validate_container_path(&config.container_path)?;
        for startup_path in &startup.mounts {
            ensure!(
                !paths_overlap(&config.container_path, startup_path),
                "target runtime output {} at {} overlaps startup mount {}; remove the path from target.startup.mounts",
                config.id,
                config.container_path.display(),
                startup_path.display()
            );
        }
    }
    for (index, left) in configs.iter().enumerate() {
        for right in configs.iter().skip(index + 1) {
            ensure!(
                !paths_overlap(&left.container_path, &right.container_path),
                "target runtime outputs {} and {} overlap at {} and {}",
                left.id,
                right.id,
                left.container_path.display(),
                right.container_path.display()
            );
        }
    }
    Ok(())
}

pub fn locations(
    root: &Path,
    role: &str,
    configs: &[RuntimeOutputConfig],
) -> Vec<RuntimeOutputLocation> {
    configs
        .iter()
        .map(|config| RuntimeOutputLocation {
            id: config.id.clone(),
            role: role.to_string(),
            container_path: config.container_path.clone(),
            host_path: root.join(&config.id),
            mode: "read_write".to_string(),
            retention: "keep".to_string(),
        })
        .collect()
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id != "."
            && id != ".."
            && id.len() <= MAX_ID_BYTES
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "target.runtime_outputs id {id:?} must contain 1-{MAX_ID_BYTES} ASCII letters, digits, '.', '_', or '-'"
    );
    Ok(())
}

fn validate_container_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path != Path::new("/"),
        "target runtime output path must be absolute and non-root: {}",
        path.display()
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "target runtime output path must be normalized: {}",
        path.display()
    );
    ensure!(
        !path.to_string_lossy().contains([',', '\r', '\n', '\t'])
            && !path.to_string_lossy().contains("//"),
        "target runtime output path contains an unsupported delimiter: {}",
        path.display()
    );
    for reserved in [
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/bin",
        "/sbin",
        "/usr",
        "/lib",
        "/lib64",
        "/run",
        "/traffic-e2e",
    ] {
        ensure!(
            !paths_overlap(path, Path::new(reserved)),
            "target runtime output path conflicts with reserved target path {reserved:?}: {}",
            path.display()
        );
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(id: &str, path: &str) -> RuntimeOutputConfig {
        RuntimeOutputConfig {
            id: id.to_string(),
            container_path: PathBuf::from(path),
            mode: RuntimeOutputMode::ReadWrite,
            retention: RuntimeOutputRetention::Keep,
        }
    }

    #[test]
    fn accepts_isolated_application_log_directory() {
        validate_configs(
            &[output("application-logs", "/data1/weibo/logs")],
            &crate::startup::StartupConfig::default(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_overlap_with_startup_mount() {
        let error = validate_configs(
            &[output("application-logs", "/data1/weibo/logs")],
            &crate::startup::StartupConfig {
                mounts: vec![PathBuf::from("/data1/weibo")],
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("overlaps startup mount"));
    }

    #[test]
    fn rejects_overlapping_runtime_outputs() {
        let error = validate_configs(
            &[
                output("logs", "/var/log/service"),
                output("audit", "/var/log/service/audit"),
            ],
            &crate::startup::StartupConfig::default(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("runtime outputs logs and audit overlap")
        );
    }

    #[test]
    fn rejects_host_path_navigation_ids_and_system_paths() {
        for id in [".", ".."] {
            assert!(
                validate_configs(
                    &[output(id, "/var/log/service")],
                    &crate::startup::StartupConfig::default(),
                )
                .is_err()
            );
        }
        assert!(
            validate_configs(
                &[output("system", "/etc")],
                &crate::startup::StartupConfig::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn derives_only_engine_owned_host_paths() {
        let location = locations(
            Path::new("/repo/.traffic-e2e/local/runtime-outputs/replay/run/sequence-000001/target"),
            "target",
            &[output("logs", "/var/log/service")],
        )
        .remove(0);
        assert_eq!(location.role, "target");
        assert_eq!(
            location.host_path,
            Path::new(
                "/repo/.traffic-e2e/local/runtime-outputs/replay/run/sequence-000001/target/logs"
            )
        );
    }
}
