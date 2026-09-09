use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod container;
mod environment;
mod image;
mod kubernetes;
mod provider;

pub use image::SourceImage;
use image::{copy_image_path, ensure_local_image};
pub use provider::{
    ContainerSourceOptions, KubernetesSourceOptions, SourceOptions, SourceProviderEvidence,
};
mod upgrade;

pub(crate) use upgrade::begin_kubernetes_source_snapshot_upgrade;

const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug, Clone, Serialize)]
pub struct SourceSnapshotReport {
    pub status: &'static str,
    pub snapshot_id: String,
    pub root: PathBuf,
    pub provider: SourceProviderEvidence,
    pub image: SourceImage,
    pub environment_variables: usize,
    pub target_environment_variables: usize,
    pub mounts: Vec<PathBuf>,
    pub ignored_mounts: Vec<SourceIgnoredMount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIgnoredMount {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceMountProjection {
    Snapshot,
    Empty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceSnapshotMount {
    pub(crate) path: PathBuf,
    pub(crate) writable: bool,
    pub(crate) projection: SourceMountProjection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceSecurityContext {
    pub(crate) privileged: bool,
    pub(crate) read_only_root_filesystem: bool,
    pub(crate) no_new_privileges: bool,
    pub(crate) capability_add: Vec<String>,
    pub(crate) capability_drop: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceRuntime {
    pub(crate) image_entrypoint: Vec<String>,
    pub(crate) image_command: Vec<String>,
    pub(crate) working_directory: Option<String>,
    pub(crate) image_user: Option<String>,
    pub(crate) pod_command: Option<Vec<String>>,
    pub(crate) pod_args: Option<Vec<String>>,
    pub(crate) security: SourceSecurityContext,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) target_environment: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceSnapshotManifest {
    schema_version: u32,
    pub(crate) snapshot_id: String,
    pub(crate) content_revision: String,
    pub(crate) provider: SourceProviderEvidence,
    pub(crate) image: SourceImage,
    pub(crate) mounts: Vec<SourceSnapshotMount>,
    pub(crate) ignored_mounts: Vec<SourceIgnoredMount>,
}

pub(crate) struct CapturedSource {
    provider: SourceProviderEvidence,
    image: SourceImage,
    runtime: SourceRuntime,
    mounts: Vec<SourceSnapshotMount>,
    ignored_mounts: Vec<SourceIgnoredMount>,
}

pub(crate) struct LoadedSourceSnapshot {
    pub(crate) manifest: SourceSnapshotManifest,
    pub(crate) runtime: SourceRuntime,
    root: PathBuf,
}

#[derive(Serialize)]
struct SourceRuntimeProjection<'a> {
    image_id: &'a str,
    pod_command: &'a Option<Vec<String>>,
    pod_args: &'a Option<Vec<String>>,
    image_command: &'a [String],
    security: &'a SourceSecurityContext,
    environment: &'a BTreeMap<String, String>,
    mounts: Vec<SourceRuntimeMountProjection>,
}

#[derive(Serialize)]
struct SourceRuntimeMountProjection {
    path: PathBuf,
    writable: bool,
    projection: SourceMountProjection,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<PathBuf>,
}

pub fn capture_kubernetes_source_snapshot(
    target_root: &Path,
    options: &KubernetesSourceOptions,
) -> Result<SourceSnapshotReport> {
    capture_source_snapshot(target_root, &SourceOptions::Kubernetes(options.clone()))
}

pub fn capture_source_snapshot(
    target_root: &Path,
    options: &SourceOptions,
) -> Result<SourceSnapshotReport> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let destination = target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            let snapshot = load(&target_root)?;
            ensure!(
                snapshot.manifest.provider.matches(options),
                "existing source snapshot belongs to another source input"
            );
            return Ok(snapshot_report("existing", snapshot));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect source snapshot {}",
                    destination.display()
                )
            });
        }
    }
    let local_root = target_root.join(crate::repository::LOCAL_ROOT);
    fs::create_dir_all(&local_root)
        .with_context(|| format!("failed to create {}", local_root.display()))?;
    fs::set_permissions(
        &local_root,
        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )?;
    let snapshot_id = Uuid::new_v4().simple().to_string();
    let staging = local_root.join(format!(".source-{snapshot_id}.staging"));
    fs::create_dir(&staging).context("failed to create source snapshot staging directory")?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    let mut captured_container_image = None;
    let result = (|| -> Result<SourceSnapshotReport> {
        let mounts_root = staging.join("mounts");
        fs::create_dir(&mounts_root).context("failed to create source mount snapshot root")?;
        let captured = options.capture(&mounts_root)?;
        if matches!(
            captured.provider,
            SourceProviderEvidence::DockerContainer { .. }
        ) {
            captured_container_image = Some(captured.image.local_id.clone());
        }
        write_json(&staging.join("runtime.json"), &captured.runtime)?;
        let content_revision = snapshot_content_revision(
            &staging,
            &captured.provider,
            &captured.image,
            &captured.mounts,
            &captured.ignored_mounts,
        )?;
        let manifest = SourceSnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: snapshot_id.clone(),
            content_revision,
            provider: captured.provider.clone(),
            image: captured.image.clone(),
            mounts: captured.mounts.clone(),
            ignored_mounts: captured.ignored_mounts.clone(),
        };
        write_json(&staging.join("manifest.json"), &manifest)?;
        load_root(&staging).context("captured source snapshot is invalid")?;
        fs::rename(&staging, &destination).with_context(|| {
            format!(
                "failed to publish source snapshot {}",
                destination.display()
            )
        })?;
        File::open(&local_root)?.sync_all()?;
        Ok(SourceSnapshotReport {
            status: "captured",
            snapshot_id,
            root: PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT),
            provider: captured.provider,
            image: captured.image,
            environment_variables: captured.runtime.environment.len(),
            target_environment_variables: captured.runtime.target_environment.len(),
            mounts: captured
                .mounts
                .into_iter()
                .map(|mount| mount.path)
                .collect(),
            ignored_mounts: captured.ignored_mounts,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
        if !destination.exists()
            && let Some(image_id) = captured_container_image
        {
            image::remove_captured_image(&image_id);
        }
    }
    result
}

fn snapshot_report(status: &'static str, snapshot: LoadedSourceSnapshot) -> SourceSnapshotReport {
    SourceSnapshotReport {
        status,
        snapshot_id: snapshot.manifest.snapshot_id,
        root: PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT),
        provider: snapshot.manifest.provider,
        image: snapshot.manifest.image,
        environment_variables: snapshot.runtime.environment.len(),
        target_environment_variables: snapshot.runtime.target_environment.len(),
        mounts: snapshot
            .manifest
            .mounts
            .into_iter()
            .map(|mount| mount.path)
            .collect(),
        ignored_mounts: snapshot.manifest.ignored_mounts,
    }
}

pub(crate) fn load(target_root: &Path) -> Result<LoadedSourceSnapshot> {
    let root = target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
    load_root(&root)
}

fn load_root(root: &Path) -> Result<LoadedSourceSnapshot> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect source snapshot {}", root.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "source snapshot root must be a directory and not a symlink: {}",
        root.display()
    );
    let manifest: SourceSnapshotManifest =
        read_json(&root.join("manifest.json")).context("source snapshot manifest is invalid")?;
    ensure!(
        manifest.schema_version == SNAPSHOT_SCHEMA_VERSION,
        "unsupported source snapshot schema"
    );
    validate_manifest(&manifest)?;
    if manifest.image.archive_sha256.is_some() {
        ensure!(
            fs::symlink_metadata(root.join("image.tar"))?.is_file(),
            "source image archive must be a regular file"
        );
    }
    let runtime: SourceRuntime =
        read_json(&root.join("runtime.json")).context("source runtime snapshot is invalid")?;
    validate_runtime(&runtime)?;
    for mount in &manifest.mounts {
        validate_snapshot_mount_path(&mount.path)?;
        if matches!(mount.projection, SourceMountProjection::Snapshot) {
            let path = snapshot_mount_path(root, &mount.path)?;
            ensure!(
                path.exists(),
                "source snapshot mount is missing: {}",
                mount.path.display()
            );
        }
    }
    for ignored in &manifest.ignored_mounts {
        validate_snapshot_mount_path(&ignored.path)?;
    }
    ensure!(
        manifest.content_revision
            == snapshot_content_revision(
                root,
                &manifest.provider,
                &manifest.image,
                &manifest.mounts,
                &manifest.ignored_mounts,
            )?,
        "source snapshot content changed"
    );
    Ok(LoadedSourceSnapshot {
        manifest,
        runtime,
        root: root.to_path_buf(),
    })
}

fn validate_manifest(manifest: &SourceSnapshotManifest) -> Result<()> {
    manifest.provider.validate()?;
    manifest.image.validate()?;
    ensure!(
        !matches!(
            manifest.provider,
            SourceProviderEvidence::KubernetesPod { .. }
        ) || manifest.image.registry_digest.is_some(),
        "Kubernetes source image requires a registry digest"
    );
    for mount in &manifest.mounts {
        validate_snapshot_mount_path(&mount.path)?;
    }
    for ignored in &manifest.ignored_mounts {
        validate_snapshot_mount_path(&ignored.path)?;
    }
    let paths = manifest
        .mounts
        .iter()
        .map(|mount| &mount.path)
        .chain(manifest.ignored_mounts.iter().map(|mount| &mount.path))
        .collect::<Vec<_>>();
    for (index, path) in paths.iter().enumerate() {
        ensure!(
            paths.iter().skip(index + 1).all(|other| {
                path != other && !path.starts_with(other) && !other.starts_with(path)
            }),
            "source snapshot mounts overlap at {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_snapshot_mount_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path != Path::new("/")
            && path.components().all(|component| matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )),
        "source snapshot mount path is invalid: {}",
        path.display()
    );
    ensure!(
        !path
            .to_string_lossy()
            .contains(['\0', '\r', '\n', '\t', ',', ':']),
        "source snapshot mount path contains an unsupported delimiter"
    );
    Ok(())
}

pub(crate) fn source_image_revision(target_root: &Path) -> Result<String> {
    Ok(load(target_root)?.manifest.image.local_id)
}

pub(crate) fn source_runtime_revision(target_root: &Path) -> Result<String> {
    Ok(load(target_root)?.manifest.content_revision)
}

pub(crate) fn target_environment(target_root: &Path) -> Result<BTreeMap<String, String>> {
    let snapshot = load(target_root)?;
    Ok(snapshot
        .runtime
        .target_environment
        .iter()
        .map(|name| {
            let value = snapshot
                .runtime
                .environment
                .get(name)
                .expect("validated target environment is present")
                .clone();
            (name.clone(), value)
        })
        .collect())
}

pub(crate) fn environment_value(target_root: &Path, name: &str) -> Result<String> {
    load(target_root)?
        .runtime
        .environment
        .get(name)
        .cloned()
        .with_context(|| format!("source snapshot has no environment variable {name:?}"))
}

pub(crate) fn write_runtime_projection(path: &Path, target_root: &Path) -> Result<()> {
    let snapshot = load(target_root)?;
    ensure_local_image(&snapshot.manifest.image, &snapshot.root)?;
    let mounts = snapshot
        .manifest
        .mounts
        .iter()
        .map(|mount| {
            let source = matches!(mount.projection, SourceMountProjection::Snapshot)
                .then(|| snapshot_mount_path(&snapshot.root, &mount.path))
                .transpose()?;
            Ok(SourceRuntimeMountProjection {
                path: mount.path.clone(),
                writable: mount.writable,
                projection: mount.projection.clone(),
                source,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    write_json(
        path,
        &SourceRuntimeProjection {
            image_id: &snapshot.manifest.image.local_id,
            pod_command: &snapshot.runtime.pod_command,
            pod_args: &snapshot.runtime.pod_args,
            image_command: &snapshot.runtime.image_command,
            security: &snapshot.runtime.security,
            environment: &snapshot.runtime.environment,
            mounts,
        },
    )
}

pub(crate) fn copy_path(target_root: &Path, path: &Path, destination: &Path) -> Result<bool> {
    crate::startup::validate_mount_path(path)?;
    let snapshot = load(target_root)?;
    if let Some(mount) = snapshot
        .manifest
        .mounts
        .iter()
        .filter(|mount| path == mount.path || path.starts_with(&mount.path))
        .max_by_key(|mount| mount.path.components().count())
    {
        if matches!(mount.projection, SourceMountProjection::Empty) {
            anyhow::bail!(
                "source path {} belongs to runtime-only mount {}; its content was not captured; create required empty writable target directories in Dockerfile.e2e",
                path.display(),
                mount.path.display()
            );
        }
        let source = snapshot_mount_path(&snapshot.root, path)?;
        ensure!(
            source.exists(),
            "source snapshot path is missing: {}",
            path.display()
        );
        clone_tree(&source, destination)?;
        return Ok(mount.writable);
    }
    if let Some(mount) = snapshot
        .manifest
        .mounts
        .iter()
        .find(|mount| mount.path.starts_with(path))
    {
        anyhow::bail!(
            "startup path {} partially overlaps source mount {}; use that exact mount path or a child path",
            path.display(),
            mount.path.display()
        );
    }
    for ignored in &snapshot.manifest.ignored_mounts {
        if path == ignored.path || path.starts_with(&ignored.path) || ignored.path.starts_with(path)
        {
            anyhow::bail!(
                "source path {} overlaps an ignored mount: {}",
                path.display(),
                ignored.reason
            );
        }
    }
    copy_image_path(&snapshot.manifest.image, &snapshot.root, path, destination)?;
    Ok(false)
}

fn validate_runtime(runtime: &SourceRuntime) -> Result<()> {
    ensure!(
        runtime.environment.len() <= 4096,
        "source environment exceeds 4096 variables"
    );
    for (name, value) in &runtime.environment {
        validate_environment_name(name)?;
        ensure!(
            !value.contains('\0'),
            "source environment {name:?} contains NUL"
        );
    }
    ensure!(
        runtime
            .target_environment
            .iter()
            .all(|name| runtime.environment.contains_key(name)),
        "source target environment references a missing value"
    );
    Ok(())
}

pub(crate) fn validate_environment_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && !name.contains(['=', '\0', '\r', '\n']) && name == name.trim(),
        "invalid source environment variable name {name:?}"
    );
    Ok(())
}

fn snapshot_mount_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = path
        .strip_prefix("/")
        .context("source snapshot mount path must be absolute")?;
    Ok(root.join("mounts").join(relative))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "source snapshot file must be regular: {}",
        path.display()
    );
    serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("failed to read {}", path.display()))
}

fn snapshot_content_revision(
    root: &Path,
    provider: &SourceProviderEvidence,
    image: &SourceImage,
    mounts: &[SourceSnapshotMount],
    ignored_mounts: &[SourceIgnoredMount],
) -> Result<String> {
    let mut hash = SnapshotHash::default();
    hash.update(&serde_json::to_vec(&(
        provider,
        image,
        mounts,
        ignored_mounts,
    ))?);
    hash.update(&[0]);
    hash_path(root, &root.join("runtime.json"), &mut hash)?;
    hash_path(root, &root.join("mounts"), &mut hash)?;
    Ok(hash.finish())
}

fn hash_path(root: &Path, path: &Path, hash: &mut SnapshotHash) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect source snapshot path {}", path.display()))?;
    hash.update(path.strip_prefix(root)?.as_os_str().as_encoded_bytes());
    hash.update(&[0]);
    if metadata.file_type().is_symlink() {
        hash.update(b"symlink\0");
        hash.update(fs::read_link(path)?.as_os_str().as_encoded_bytes());
        return Ok(());
    }
    if metadata.is_dir() {
        hash.update(b"directory\0");
        let mut children = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        for child in children {
            hash_path(root, &child, hash)?;
        }
        return Ok(());
    }
    ensure!(metadata.is_file(), "unsupported source snapshot file type");
    hash.update(b"file\0");
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(())
}

fn clone_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(source)?, destination)?;
    } else if metadata.is_dir() {
        fs::create_dir(destination)?;
        fs::set_permissions(destination, metadata.permissions())?;
        let mut children = fs::read_dir(source)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        for child in children {
            clone_tree(
                &child,
                &destination.join(child.file_name().expect("child name")),
            )?;
        }
    } else {
        ensure!(metadata.is_file(), "unsupported source snapshot file type");
        fs::copy(source, destination)?;
        fs::set_permissions(destination, metadata.permissions())?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest() -> SourceSnapshotManifest {
        SourceSnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            snapshot_id: "snapshot-test".to_string(),
            content_revision: "pending".to_string(),
            provider: SourceProviderEvidence::KubernetesPod {
                context: None,
                namespace: "default".to_string(),
                pod: "source".to_string(),
                pod_uid: "pod-uid".to_string(),
                container: "app".to_string(),
                restart_count: 0,
            },
            image: SourceImage {
                reference: "example/app:1".to_string(),
                registry_digest: Some(format!("example/app@sha256:{}", "a".repeat(64))),
                archive_sha256: None,
                local_id: format!("sha256:{}", "b".repeat(64)),
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
            },
            mounts: Vec::new(),
            ignored_mounts: Vec::new(),
        }
    }

    #[test]
    fn manifest_rejects_overlap_between_supported_and_ignored_mounts() {
        let mut manifest = test_manifest();
        manifest.mounts.push(SourceSnapshotMount {
            path: PathBuf::from("/data/app"),
            writable: false,
            projection: SourceMountProjection::Snapshot,
        });
        manifest.ignored_mounts.push(SourceIgnoredMount {
            path: PathBuf::from("/data/app/token"),
            reason: "unsupported projection".to_string(),
        });

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn target_environment_uses_source_baseline_and_target_overrides() {
        let target = tempfile::tempdir().unwrap();
        let root = target.path().join(crate::repository::LOCAL_SOURCE_ROOT);
        fs::create_dir_all(root.join("mounts")).unwrap();
        let runtime = SourceRuntime {
            image_entrypoint: Vec::new(),
            image_command: Vec::new(),
            working_directory: Some("/app".to_string()),
            image_user: None,
            pod_command: None,
            pod_args: None,
            security: SourceSecurityContext::default(),
            environment: BTreeMap::from([
                ("DATABASE_URL".to_string(), "mysql://source".to_string()),
                ("HOSTNAME".to_string(), "pod-name".to_string()),
                ("PORT".to_string(), "8080".to_string()),
            ]),
            target_environment: BTreeSet::from(["DATABASE_URL".to_string(), "PORT".to_string()]),
        };
        write_json(&root.join("runtime.json"), &runtime).unwrap();
        let mut manifest = test_manifest();
        manifest.content_revision = snapshot_content_revision(
            &root,
            &manifest.provider,
            &manifest.image,
            &manifest.mounts,
            &manifest.ignored_mounts,
        )
        .unwrap();
        write_json(&root.join("manifest.json"), &manifest).unwrap();
        let reused = capture_kubernetes_source_snapshot(
            target.path(),
            &KubernetesSourceOptions {
                pod: "source".to_string(),
                namespace: "default".to_string(),
                container: Some("app".to_string()),
                kubeconfig: Some(PathBuf::from("/missing/kubeconfig")),
                context: None,
                kubectl_binary: PathBuf::from("missing-kubectl"),
            },
        )
        .unwrap();
        assert_eq!(reused.status, "existing");
        assert_eq!(reused.environment_variables, 3);
        crate::startup::initialize_startup_environment(target.path(), None).unwrap();

        assert!(
            crate::startup::startup_environment_equals(
                target.path(),
                "DATABASE_URL",
                "mysql://source",
            )
            .unwrap()
            .equal
        );
        assert_eq!(
            crate::startup::ensure_startup_environment(
                target.path(),
                "DATABASE_URL",
                "mysql://source",
            )
            .unwrap()
            .status,
            crate::startup::StartupEnvironmentChangeStatus::Unchanged
        );
        crate::startup::ensure_startup_environment(target.path(), "PORT", "9090").unwrap();
        let projection = target.path().join("target.env");
        crate::startup::write_docker_environment_file(&projection, target.path()).unwrap();
        assert_eq!(
            fs::read_to_string(projection).unwrap(),
            "DATABASE_URL=mysql://source\nPORT=9090\n"
        );
        let listed = crate::startup::list_startup_environment(target.path()).unwrap();
        assert_eq!(listed.variables, ["DATABASE_URL", "PORT"]);
        assert_eq!(listed.overrides, ["PORT"]);
    }
}
