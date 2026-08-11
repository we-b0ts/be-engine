use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

mod snapshot;

pub(crate) use snapshot::{
    LoadedStartupSnapshot, StartupSnapshotMount, capture_startup_snapshot, load_startup_snapshot,
    startup_mount_source, startup_snapshot_revision,
};

const ENVIRONMENT_FILE_MODE: u32 = 0o600;
const MAX_STARTUP_MOUNTS: usize = 64;
const MAX_STARTUP_ENVIRONMENT: usize = 128;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_from_source: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_ca_environment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupSnapshotReport {
    pub status: &'static str,
    pub snapshot_id: String,
    pub root: PathBuf,
    pub mounts: Vec<PathBuf>,
    pub writable_mounts: Vec<PathBuf>,
    pub environment: Vec<String>,
    pub source_container_id: String,
    pub source_image_id: String,
}

pub(crate) fn normalized_config(mut config: StartupConfig) -> Result<StartupConfig> {
    config.mounts.sort();
    config.mounts.dedup();
    config.environment_from_source.sort();
    config.environment_from_source.dedup();
    validate_config(&config)?;
    Ok(config)
}

pub(crate) fn validate_config(config: &StartupConfig) -> Result<()> {
    ensure!(
        config.mounts.len() <= MAX_STARTUP_MOUNTS,
        "startup mounts exceed the limit of {MAX_STARTUP_MOUNTS}"
    );
    ensure!(
        config.environment_from_source.len() <= MAX_STARTUP_ENVIRONMENT,
        "startup environment exceeds the limit of {MAX_STARTUP_ENVIRONMENT}"
    );
    let mut mounts = BTreeSet::<PathBuf>::new();
    for mount in &config.mounts {
        validate_mount_path(mount)?;
        ensure!(
            mounts.insert(mount.clone()),
            "duplicate startup mount {}",
            mount.display()
        );
    }
    let mounts = mounts.into_iter().collect::<Vec<_>>();
    for (index, parent) in mounts.iter().enumerate() {
        for child in mounts.iter().skip(index + 1) {
            ensure!(
                !child.starts_with(parent),
                "startup mounts must not overlap: {} and {}",
                parent.display(),
                child.display()
            );
        }
    }
    let mut names = BTreeSet::<String>::new();
    for name in &config.environment_from_source {
        validate_environment_name(name)?;
        ensure!(
            names.insert(name.clone()),
            "duplicate startup environment {name:?}"
        );
    }
    for (label, name) in [
        ("target port", config.port_environment.as_deref()),
        ("Replay CA", config.replay_ca_environment.as_deref()),
    ] {
        if let Some(name) = name {
            validate_environment_name(name)?;
            ensure!(
                names.insert(name.to_string()),
                "{label} environment {name:?} conflicts with another startup environment"
            );
        }
    }
    Ok(())
}

pub(super) fn validate_mount_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "startup mount must be absolute: {}",
        path.display()
    );
    ensure!(path != Path::new("/"), "startup mount must not target /");
    for component in path.components() {
        ensure!(
            matches!(component, Component::RootDir | Component::Normal(_)),
            "startup mount must be normalized: {}",
            path.display()
        );
    }
    let text = path.to_string_lossy();
    ensure!(
        !text.contains([',', '\r', '\n', '\t']),
        "startup mount contains an unsupported delimiter: {}",
        path.display()
    );
    for reserved in ["/proc", "/sys", "/dev", "/traffic-e2e"] {
        let reserved = Path::new(reserved);
        ensure!(
            path != reserved && !path.starts_with(reserved) && !reserved.starts_with(path),
            "startup mount conflicts with reserved target path {reserved:?}: {}",
            path.display()
        );
    }
    ensure!(
        path != Path::new("/app") && !Path::new("/app").starts_with(path),
        "startup mount conflicts with reserved target path \"/app\": {}",
        path.display()
    );
    for managed in ["/data1/breeze/socks", "/data1/breeze/snapshot"] {
        let managed = Path::new(managed);
        ensure!(
            path != managed && !path.starts_with(managed) && !managed.starts_with(path),
            "startup mount conflicts with managed Breeze path {managed:?}: {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    ensure!(
        bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()),
        "invalid startup environment variable name {name:?}"
    );
    ensure!(
        !name.to_ascii_uppercase().starts_with("TRAFFIC_E2E_"),
        "startup environment must use an application-owned name, got {name:?}"
    );
    Ok(())
}

pub(crate) fn write_docker_environment_file(
    path: &Path,
    snapshot: &LoadedStartupSnapshot,
    config: &StartupConfig,
    port: u16,
    replay_ca: bool,
    replay_ca_path: &str,
) -> Result<bool> {
    let mut values = snapshot.environment.clone();
    if let Some(name) = &config.port_environment {
        values.insert(name.clone(), port.to_string());
    }
    if replay_ca && let Some(name) = &config.replay_ca_environment {
        values.insert(name.clone(), replay_ca_path.to_string());
    }
    if values.is_empty() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ENVIRONMENT_FILE_MODE)
        .open(path)
        .with_context(|| {
            format!(
                "failed to create Docker environment file {}",
                path.display()
            )
        })?;
    for (name, value) in values {
        ensure!(
            !value.contains(['\r', '\n']),
            "startup environment {name:?} contains a newline unsupported by Docker env files"
        );
        writeln!(file, "{name}={value}")?;
    }
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(ENVIRONMENT_FILE_MODE))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_mounts_are_absolute_source_compatible_paths() {
        assert!(validate_mount_path(Path::new("/data1/weibo/confs")).is_ok());
        assert!(validate_mount_path(Path::new("data1/weibo/confs")).is_err());
        assert!(validate_mount_path(Path::new("/app/config")).is_ok());
        assert!(validate_mount_path(Path::new("/app")).is_err());
        assert!(validate_mount_path(Path::new("/data1")).is_err());
    }

    #[test]
    fn startup_environment_names_are_application_owned() {
        assert!(validate_environment_name("WEIBO_CONF_PATH").is_ok());
        assert!(validate_environment_name("TRAFFIC_E2E_CONFIG_DIR").is_err());
        assert!(validate_environment_name("not-valid").is_err());
    }

    #[test]
    fn overlapping_mounts_are_rejected() {
        let error = validate_config(&StartupConfig {
            mounts: vec![
                PathBuf::from("/opt/config"),
                PathBuf::from("/opt/config/app"),
            ],
            ..StartupConfig::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("must not overlap"));
    }
}
