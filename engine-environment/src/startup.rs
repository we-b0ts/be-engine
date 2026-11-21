use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

mod environment;
mod snapshot;

#[cfg(any(test, feature = "test-support"))]
pub use snapshot::test_support::install_startup_snapshot;

pub use environment::{
    StartupEnvironmentChange, StartupEnvironmentChangeStatus, StartupEnvironmentComparison,
    StartupEnvironmentImport, StartupEnvironmentList, StartupEnvironmentPresence,
    StartupEnvironmentValidation, ensure_startup_environment, import_startup_environment,
    initialize_startup_environment, list_startup_environment, remove_startup_environment,
    startup_environment_equals, startup_environment_exists, validate_startup_environment,
};
pub use environment::{
    startup_environment_revision, startup_environment_value, startup_environment_variable_names,
    startup_environment_witness_paths, write_docker_environment_file,
};
pub use snapshot::{
    StartupSnapshotMount, capture_startup_snapshot, extend_startup_snapshot, load_startup_snapshot,
    startup_mount_source, startup_snapshot_revision,
};

const MAX_STARTUP_MOUNTS: usize = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupSnapshotReport {
    pub status: &'static str,
    pub snapshot_id: String,
    pub root: PathBuf,
    pub mounts: Vec<PathBuf>,
    pub writable_mounts: Vec<PathBuf>,
    pub source_snapshot_id: String,
    pub source_image_id: String,
}

pub fn normalized_config(mut config: StartupConfig) -> Result<StartupConfig> {
    config.mounts.sort();
    config.mounts.dedup();
    validate_config(&config)?;
    Ok(config)
}

pub fn validate_config(config: &StartupConfig) -> Result<()> {
    ensure!(
        config.mounts.len() <= MAX_STARTUP_MOUNTS,
        "startup mounts exceed the limit of {MAX_STARTUP_MOUNTS}"
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
    Ok(())
}

pub fn validate_mount_path(path: &Path) -> Result<()> {
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
    Ok(())
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
        assert!(validate_mount_path(Path::new("/data1")).is_ok());
        assert!(validate_mount_path(Path::new("/data1/mounts/cache")).is_ok());
    }

    #[test]
    fn overlapping_mounts_are_rejected() {
        let error = validate_config(&StartupConfig {
            mounts: vec![
                PathBuf::from("/opt/config"),
                PathBuf::from("/opt/config/app"),
            ],
        })
        .unwrap_err();
        assert!(error.to_string().contains("must not overlap"));
    }
}
