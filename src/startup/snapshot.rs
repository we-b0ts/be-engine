use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{StartupConfig, StartupSnapshotReport, validate_config, validate_mount_path};

const SNAPSHOT_SCHEMA_VERSION: u32 = 2;
const ENVIRONMENT_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartupManifest {
    schema_version: u32,
    pub(crate) snapshot_id: String,
    content_revision: String,
    pub(crate) source_container_id: String,
    pub(crate) source_image_id: String,
    mounts: Vec<StartupSnapshotMount>,
    environment: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartupSnapshotMount {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupEnvironment {
    schema_version: u32,
    snapshot_id: String,
    values: BTreeMap<String, String>,
}

#[derive(Debug)]
pub(crate) struct LoadedStartupSnapshot {
    pub(crate) manifest: StartupManifest,
    pub(crate) environment: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SourceInspection {
    pub(super) id: String,
    pub(super) image: String,
    pub(super) state: SourceState,
    #[serde(default)]
    pub(super) mounts: Vec<SourceMountInspection>,
    config: SourceConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SourceMountInspection {
    destination: PathBuf,
    #[serde(rename = "RW")]
    writable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SourceState {
    pub(super) running: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SourceConfig {
    env: Option<Vec<String>>,
}

pub(crate) fn capture_startup_snapshot(
    target_root: &Path,
    source_container: &str,
    config: &StartupConfig,
) -> Result<StartupSnapshotReport> {
    validate_config(config)?;
    let source = inspect_source(source_container)?;
    ensure!(
        !source.state.running,
        "configured source container {source_container:?} must be stopped before capturing startup inputs"
    );
    let source_environment = parse_source_environment(source.config.env.unwrap_or_default());
    let mounts = resolve_startup_mounts(&config.mounts, &source.mounts)?;
    let values = config
        .environment_from_source
        .iter()
        .map(|name| {
            source_environment
                .get(name)
                .cloned()
                .map(|value| (name.clone(), value))
                .with_context(|| {
                    format!(
                        "configured source container {source_container:?} does not declare required environment {name:?}"
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let snapshot_id = Uuid::new_v4().simple().to_string();
    let local_root = target_root.join(crate::repository::LOCAL_ROOT);
    fs::create_dir_all(&local_root).with_context(|| {
        format!(
            "failed to create local startup parent {}",
            local_root.display()
        )
    })?;
    let staging = local_root.join(format!(".startup-{snapshot_id}.staging"));
    ensure!(!staging.exists(), "startup staging path already exists");
    let mounts_root = staging.join("mounts");
    fs::create_dir_all(&mounts_root).context("failed to create startup mounts staging root")?;
    let result = (|| -> Result<StartupSnapshotReport> {
        for mount in &config.mounts {
            copy_mount(source_container, mount, &mounts_root)?;
        }
        let content_revision = snapshot_content_revision(&mounts_root, &values)?;
        let manifest = StartupManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: snapshot_id.clone(),
            content_revision,
            source_container_id: source.id.clone(),
            source_image_id: source.image.clone(),
            mounts: mounts.clone(),
            environment: config.environment_from_source.clone(),
        };
        let environment = StartupEnvironment {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: snapshot_id.clone(),
            values,
        };
        write_json(&staging.join("manifest.json"), &manifest, 0o600)?;
        write_json(
            &staging.join("environment.json"),
            &environment,
            ENVIRONMENT_FILE_MODE,
        )?;
        publish_staging(&local_root, &staging, &snapshot_id)?;
        Ok(StartupSnapshotReport {
            status: "captured",
            snapshot_id,
            root: PathBuf::from(crate::repository::LOCAL_STARTUP_ROOT),
            mounts: config.mounts.clone(),
            writable_mounts: mounts
                .iter()
                .filter(|mount| mount.writable)
                .map(|mount| mount.path.clone())
                .collect(),
            environment: config.environment_from_source.clone(),
            source_container_id: source.id,
            source_image_id: source.image,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub(super) fn inspect_source(container: &str) -> Result<SourceInspection> {
    ensure!(
        container == container.trim()
            && !container.is_empty()
            && !container.contains(['\r', '\n', ':']),
        "source container name must be non-empty and single-line"
    );
    let output = Command::new("docker")
        .args(["container", "inspect", container])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to inspect source container {container:?}"))?;
    ensure!(
        output.status.success(),
        "source container {container:?} is not inspectable: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut values: Vec<SourceInspection> = serde_json::from_slice(&output.stdout)
        .context("Docker returned invalid source container inspection JSON")?;
    ensure!(
        values.len() == 1,
        "Docker returned {} source container inspections",
        values.len()
    );
    Ok(values.remove(0))
}

fn parse_source_environment(values: Vec<String>) -> BTreeMap<String, String> {
    let mut parsed = BTreeMap::new();
    for value in values {
        if let Some((name, value)) = value.split_once('=') {
            parsed.insert(name.to_string(), value.to_string());
        }
    }
    parsed
}

fn copy_mount(container: &str, mount: &Path, mounts_root: &Path) -> Result<()> {
    let relative = mount.strip_prefix("/").expect("validated absolute mount");
    let destination = mounts_root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create startup path {}", parent.display()))?;
    }
    let source = format!("{container}:{}", mount.display());
    let output = Command::new("docker")
        .args(["cp", "--archive", &source])
        .arg(&destination)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to copy startup input {}", mount.display()))?;
    ensure!(
        output.status.success(),
        "failed to copy startup input {} from source container: {}",
        mount.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let metadata = fs::symlink_metadata(&destination)
        .with_context(|| format!("copied startup input is missing: {}", destination.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "startup mount root must not be a symlink: {}",
        mount.display()
    );
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn publish_staging(local_root: &Path, staging: &Path, snapshot_id: &str) -> Result<()> {
    let startup = local_root.join("startup");
    let previous = local_root.join(format!(".startup-{snapshot_id}.previous"));
    if startup.exists() {
        fs::rename(&startup, &previous).context("failed to preserve previous startup snapshot")?;
    }
    if let Err(error) = fs::rename(staging, &startup) {
        if previous.exists() {
            let _ = fs::rename(&previous, &startup);
        }
        return Err(error).context("failed to publish startup snapshot");
    }
    if previous.exists() {
        fs::remove_dir_all(&previous).context("failed to remove previous startup snapshot")?;
    }
    File::open(local_root)
        .and_then(|directory| directory.sync_all())
        .context("failed to sync startup snapshot parent")?;
    Ok(())
}

pub(crate) fn load_startup_snapshot(
    target_root: &Path,
    config: &StartupConfig,
) -> Result<LoadedStartupSnapshot> {
    validate_config(config)?;
    let manifest_path = target_root.join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH);
    let environment_path = target_root.join(crate::repository::LOCAL_STARTUP_ENVIRONMENT_PATH);
    let manifest: StartupManifest =
        serde_json::from_slice(&fs::read(&manifest_path).with_context(|| {
            format!("startup snapshot is missing: {}", manifest_path.display())
        })?)
        .context("startup manifest is invalid")?;
    let environment: StartupEnvironment =
        serde_json::from_slice(&fs::read(&environment_path).with_context(|| {
            format!(
                "startup environment is missing: {}",
                environment_path.display()
            )
        })?)
        .context("startup environment snapshot is invalid")?;
    ensure!(
        manifest.schema_version == SNAPSHOT_SCHEMA_VERSION
            && environment.schema_version == SNAPSHOT_SCHEMA_VERSION,
        "unsupported startup snapshot schema"
    );
    ensure!(
        manifest.snapshot_id == environment.snapshot_id,
        "startup manifest and environment snapshot do not match"
    );
    ensure!(
        manifest
            .mounts
            .iter()
            .map(|mount| &mount.path)
            .eq(config.mounts.iter())
            && manifest.environment == config.environment_from_source,
        "startup snapshot is stale; run `backend-rewrite startup refresh`"
    );
    ensure!(
        environment
            .values
            .keys()
            .eq(config.environment_from_source.iter()),
        "startup environment snapshot does not match configured names"
    );
    for mount in &manifest.mounts {
        let source = startup_mount_source(target_root, &mount.path)?;
        ensure!(
            source.exists(),
            "startup mount is missing: {}",
            source.display()
        );
    }
    let mounts_root = target_root.join(crate::repository::LOCAL_STARTUP_MOUNTS_ROOT);
    ensure!(
        manifest.content_revision == snapshot_content_revision(&mounts_root, &environment.values)?,
        "startup snapshot content changed; run `backend-rewrite startup refresh`"
    );
    Ok(LoadedStartupSnapshot {
        manifest,
        environment: environment.values,
    })
}

pub(crate) fn startup_snapshot_revision(target_root: &Path) -> Result<String> {
    let path = target_root.join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH);
    match fs::read(&path) {
        Ok(bytes) => {
            let manifest: StartupManifest =
                serde_json::from_slice(&bytes).context("startup manifest is invalid")?;
            ensure!(
                manifest.schema_version == SNAPSHOT_SCHEMA_VERSION,
                "unsupported startup snapshot schema"
            );
            Ok(manifest.snapshot_id)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok("startup:absent".to_string())
        }
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn snapshot_content_revision(
    mounts_root: &Path,
    environment: &BTreeMap<String, String>,
) -> Result<String> {
    let mut hash = SnapshotHash::default();
    hash.update(b"environment\0");
    for (name, value) in environment {
        hash.update(name.as_bytes());
        hash.update(&[0]);
        hash.update(value.as_bytes());
        hash.update(&[0]);
    }
    hash.update(b"mounts\0");
    hash_snapshot_path(mounts_root, mounts_root, &mut hash)?;
    Ok(hash.finish())
}

fn hash_snapshot_path(root: &Path, path: &Path, hash: &mut SnapshotHash) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect startup snapshot path {}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .expect("snapshot path is under root");
    hash.update(relative.as_os_str().as_encoded_bytes());
    hash.update(&[0]);
    if metadata.file_type().is_symlink() {
        hash.update(b"symlink\0");
        hash.update(fs::read_link(path)?.as_os_str().as_encoded_bytes());
        hash.update(&[0]);
        return Ok(());
    }
    if metadata.is_dir() {
        hash.update(b"directory\0");
        let mut children = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        for child in children {
            hash_snapshot_path(root, &child, hash)?;
        }
        return Ok(());
    }
    ensure!(
        metadata.is_file(),
        "startup snapshot contains an unsupported file type: {}",
        path.display()
    );
    hash.update(b"file\0");
    hash.update(&metadata.len().to_le_bytes());
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    hash.update(&[0]);
    Ok(())
}

struct SnapshotHash(u64);

impl Default for SnapshotHash {
    fn default() -> Self {
        Self(0xcbf29ce484222325)
    }
}

impl SnapshotHash {
    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(self) -> String {
        format!("fnv1a64:{:016x}", self.0)
    }
}

pub(super) fn resolve_startup_mounts(
    configured: &[PathBuf],
    source_mounts: &[SourceMountInspection],
) -> Result<Vec<StartupSnapshotMount>> {
    configured
        .iter()
        .map(|path| {
            let mut writable = false;
            let mut exact_match = false;
            for source_mount in source_mounts {
                validate_source_mount_destination(&source_mount.destination)?;
                if source_mount.destination == *path {
                    ensure!(
                        !exact_match,
                        "source container has duplicate mount destination {}",
                        path.display()
                    );
                    exact_match = true;
                    writable = source_mount.writable;
                } else if source_mount.destination.starts_with(path)
                    || path.starts_with(&source_mount.destination)
                {
                    anyhow::bail!(
                        "startup path {} partially overlaps source mount destination {}; use an exact startup path or narrow the declaration",
                        path.display(),
                        source_mount.destination.display()
                    );
                }
            }
            Ok(StartupSnapshotMount {
                path: path.clone(),
                writable,
            })
        })
        .collect()
}

fn validate_source_mount_destination(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path != Path::new("/"),
        "source mount destination must be an absolute non-root path: {}",
        path.display()
    );
    ensure!(
        path.components().all(|component| matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "source mount destination must be normalized: {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn startup_mount_source(target_root: &Path, mount: &Path) -> Result<PathBuf> {
    validate_mount_path(mount)?;
    Ok(target_root
        .join(crate::repository::LOCAL_STARTUP_MOUNTS_ROOT)
        .join(mount.strip_prefix("/").expect("validated absolute mount")))
}

impl LoadedStartupSnapshot {
    pub(crate) fn mounts(&self) -> &[StartupSnapshotMount] {
        &self.manifest.mounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_content_revision_changes_with_mount_or_environment() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("config"), "one").unwrap();
        let environment = BTreeMap::from([("WEIBO_CONF_PATH".to_string(), "/one".to_string())]);
        let first = snapshot_content_revision(root.path(), &environment).unwrap();
        fs::write(root.path().join("config"), "two").unwrap();
        let second = snapshot_content_revision(root.path(), &environment).unwrap();
        let changed_environment =
            BTreeMap::from([("WEIBO_CONF_PATH".to_string(), "/two".to_string())]);
        let third = snapshot_content_revision(root.path(), &changed_environment).unwrap();
        assert_ne!(first, second);
        assert_ne!(second, third);
    }

    #[test]
    fn exact_source_mount_inherits_writable_mode() {
        let configured = vec![PathBuf::from("/data1/openapi-config")];
        let resolved = resolve_startup_mounts(
            &configured,
            &[SourceMountInspection {
                destination: PathBuf::from("/data1/openapi-config"),
                writable: true,
            }],
        )
        .unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].path, configured[0]);
        assert!(resolved[0].writable);
    }

    #[test]
    fn image_startup_path_defaults_to_read_only() {
        let configured = vec![PathBuf::from("/data1/confs")];
        let resolved = resolve_startup_mounts(&configured, &[]).unwrap();
        assert!(!resolved[0].writable);
    }

    #[test]
    fn partial_source_mount_overlap_is_rejected() {
        let configured = vec![PathBuf::from("/data1/app")];
        let error = resolve_startup_mounts(
            &configured,
            &[SourceMountInspection {
                destination: PathBuf::from("/data1/app/logs"),
                writable: true,
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("partially overlaps"));
    }
}
