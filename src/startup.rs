use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

mod snapshot;

use snapshot::inspect_source;
pub(crate) use snapshot::{
    LoadedStartupSnapshot, capture_startup_snapshot, load_startup_snapshot, startup_mount_source,
    startup_snapshot_revision,
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

#[derive(Debug, Clone)]
pub struct StartupUpdateOptions {
    pub target_root: PathBuf,
    pub config: StartupConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupSnapshotReport {
    pub status: &'static str,
    pub snapshot_id: String,
    pub root: PathBuf,
    pub mounts: Vec<PathBuf>,
    pub environment: Vec<String>,
    pub source_container_id: String,
    pub source_image_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupStatusReport {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    pub root: PathBuf,
    pub mounts: Vec<PathBuf>,
    pub environment: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_image_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_running: Option<bool>,
    pub stale: bool,
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

pub fn refresh_startup_snapshot(target_root: &Path) -> Result<StartupSnapshotReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(target_root)?;
    capture_startup_snapshot(
        &target_root,
        &project.source_container,
        &project.target_startup,
    )
}

pub fn update_startup_snapshot(options: StartupUpdateOptions) -> Result<StartupSnapshotReport> {
    let config = normalized_config(options.config)?;
    let (target_root, source_container, previous) =
        crate::e2e_run::resolve_startup_update_context(&options.target_root)?;
    let report = capture_startup_snapshot(&target_root, &source_container, &config)?;
    if let Err(error) = crate::e2e_run::update_project_startup(&target_root, config) {
        return match previous {
            Some(previous) => match capture_startup_snapshot(
                &target_root,
                &source_container,
                &previous,
            ) {
                Ok(_) => Err(error).context(
                    "project configuration could not be updated; the previous startup snapshot was restored",
                ),
                Err(restore_error) => Err(anyhow::anyhow!(
                    "project configuration could not be updated: {error:#}; restoring the previous startup snapshot also failed: {restore_error:#}"
                )),
            },
            None => Err(error).context(
                "legacy project configuration could not be migrated after capturing the startup snapshot",
            ),
        };
    }
    Ok(report)
}

pub fn status_startup_snapshot(target_root: &Path) -> Result<StartupStatusReport> {
    let (target_root, project) = crate::e2e_run::resolve_project(target_root)?;
    let root = PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT);
    match load_startup_snapshot(&target_root, &project.target_startup) {
        Ok(snapshot) => {
            let current = inspect_source(&project.source_container)?;
            let stale = current.id != snapshot.manifest.source_container_id
                || current.image != snapshot.manifest.source_image_id;
            Ok(StartupStatusReport {
                status: if current.state.running {
                    "source_running"
                } else if stale {
                    "stale"
                } else {
                    "ready"
                },
                snapshot_id: Some(snapshot.manifest.snapshot_id),
                root,
                mounts: project.target_startup.mounts,
                environment: project.target_startup.environment_from_source,
                stale,
                source_container_id: Some(snapshot.manifest.source_container_id),
                source_image_id: Some(snapshot.manifest.source_image_id),
                source_running: Some(current.state.running),
            })
        }
        Err(_) => Ok(StartupStatusReport {
            status: "missing_or_stale",
            snapshot_id: None,
            root,
            mounts: project.target_startup.mounts,
            environment: project.target_startup.environment_from_source,
            source_container_id: None,
            source_image_id: None,
            source_running: None,
            stale: true,
        }),
    }
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
