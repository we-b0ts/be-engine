use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;

use super::{
    CapturedSource, KubernetesSourceOptions, SourceIgnoredMount, SourceImage,
    SourceMountProjection, SourceProviderEvidence, SourceRuntime, SourceSecurityContext,
    SourceSnapshotMount, environment::is_target_environment_name, validate_environment_name,
};

const MAX_KUBECTL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_ENVIRONMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SOURCE_ENVIRONMENT_VARIABLES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pod {
    metadata: PodMetadata,
    spec: PodSpec,
    status: PodStatus,
}

#[derive(Debug, Deserialize)]
struct PodMetadata {
    name: String,
    namespace: String,
    uid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    containers: Vec<PodContainer>,
    #[serde(default)]
    volumes: Vec<PodVolume>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodContainer {
    name: String,
    image: String,
    command: Option<Vec<String>>,
    args: Option<Vec<String>>,
    #[serde(default)]
    env: Vec<PodEnvironment>,
    #[serde(default)]
    env_from: Vec<PodEnvironmentFrom>,
    #[serde(default)]
    volume_mounts: Vec<PodVolumeMount>,
    security_context: Option<PodSecurityContext>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodEnvironment {
    name: String,
    value: Option<String>,
    value_from: Option<PodEnvironmentValueFrom>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodEnvironmentValueFrom {
    config_map_key_ref: Option<Value>,
    secret_key_ref: Option<Value>,
    field_ref: Option<Value>,
    resource_field_ref: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodEnvironmentFrom {
    prefix: Option<String>,
    config_map_ref: Option<Value>,
    secret_ref: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodVolumeMount {
    name: String,
    mount_path: PathBuf,
    #[serde(default)]
    read_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSecurityContext {
    #[serde(default)]
    privileged: bool,
    #[serde(default)]
    read_only_root_filesystem: bool,
    allow_privilege_escalation: Option<bool>,
    capabilities: Option<PodCapabilities>,
}

#[derive(Debug, Deserialize)]
struct PodCapabilities {
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    drop: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodVolume {
    name: String,
    config_map: Option<Value>,
    secret: Option<Value>,
    projected: Option<ProjectedVolume>,
    host_path: Option<Value>,
    persistent_volume_claim: Option<Value>,
    empty_dir: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ProjectedVolume {
    #[serde(default)]
    sources: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodStatus {
    phase: Option<String>,
    #[serde(default)]
    container_statuses: Vec<PodContainerStatus>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodContainerStatus {
    name: String,
    #[serde(rename = "imageID")]
    image_id: String,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    restart_count: u32,
    state: PodContainerState,
}

#[derive(Debug, Clone, Deserialize)]
struct PodContainerState {
    running: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerImageInspection {
    id: String,
    architecture: String,
    os: String,
    config: DockerImageConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerImageConfig {
    #[serde(default)]
    entrypoint: Option<Vec<String>>,
    #[serde(default)]
    cmd: Option<Vec<String>>,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    env: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum VolumeKind {
    Snapshot,
    Empty,
    Ignored,
}

pub(super) fn capture(
    options: &KubernetesSourceOptions,
    mounts_root: &Path,
) -> Result<CapturedSource> {
    validate_options(options)?;
    let before = get_pod(options)?;
    ensure!(
        before.metadata.name == options.pod && before.metadata.namespace == options.namespace,
        "kubectl returned a different source Pod"
    );
    ensure!(
        before.status.phase.as_deref() == Some("Running"),
        "source Pod {}/{} must be Running",
        options.namespace,
        options.pod
    );
    let container = select_container(&before, options.container.as_deref())?;
    let status = select_status(&before, &container.name)?;
    ensure!(
        status.state.running.is_some() && status.ready,
        "source Pod container {:?} must be running and ready",
        container.name
    );
    let registry_digest = normalize_registry_digest(&status.image_id)?;
    let (image, image_config) = resolve_image(&container.image, &registry_digest)?;
    let environment = read_effective_environment(options, &container.name)?;
    let target_environment = target_environment_names(container, &image_config, &environment)?;
    let (mounts, ignored_mounts) = capture_mounts(options, &before, container, mounts_root)?;
    let after = get_pod(options)?;
    let after_status = select_status(&after, &container.name)?;
    ensure!(
        before.metadata.uid == after.metadata.uid
            && status.image_id == after_status.image_id
            && status.restart_count == after_status.restart_count
            && after_status.state.running.is_some(),
        "source Pod changed while its runtime snapshot was being captured; retry initialization"
    );
    let security = container
        .security_context
        .as_ref()
        .map(|context| SourceSecurityContext {
            privileged: context.privileged,
            read_only_root_filesystem: context.read_only_root_filesystem,
            no_new_privileges: context.allow_privilege_escalation == Some(false),
            capability_add: context
                .capabilities
                .as_ref()
                .map(|capabilities| capabilities.add.clone())
                .unwrap_or_default(),
            capability_drop: context
                .capabilities
                .as_ref()
                .map(|capabilities| capabilities.drop.clone())
                .unwrap_or_default(),
        })
        .unwrap_or_default();
    Ok(CapturedSource {
        provider: SourceProviderEvidence::KubernetesPod {
            context: options.context.clone(),
            namespace: before.metadata.namespace.clone(),
            pod: before.metadata.name.clone(),
            pod_uid: before.metadata.uid.clone(),
            container: container.name.clone(),
            restart_count: status.restart_count,
        },
        image,
        runtime: SourceRuntime {
            image_entrypoint: image_config.entrypoint.unwrap_or_default(),
            image_command: image_config.cmd.unwrap_or_default(),
            working_directory: nonempty(image_config.working_dir),
            image_user: nonempty(image_config.user),
            pod_command: container.command.clone(),
            pod_args: container.args.clone(),
            security,
            environment,
            target_environment,
        },
        mounts,
        ignored_mounts,
    })
}

fn validate_options(options: &KubernetesSourceOptions) -> Result<()> {
    for (name, value) in [
        ("source Pod", options.pod.as_str()),
        ("source namespace", options.namespace.as_str()),
    ] {
        ensure!(
            !value.is_empty() && value == value.trim() && !value.contains(['\r', '\n']),
            "{name} must be non-empty and single-line"
        );
    }
    if let Some(container) = &options.container {
        ensure!(
            !container.is_empty()
                && container == container.trim()
                && !container.contains(['\r', '\n']),
            "source Pod container must be non-empty and single-line"
        );
    }
    ensure!(
        !options.kubectl_binary.as_os_str().is_empty(),
        "kubectl binary must not be empty"
    );
    if let Some(kubeconfig) = &options.kubeconfig {
        ensure!(
            kubeconfig.is_file(),
            "kubeconfig does not exist: {}",
            kubeconfig.display()
        );
    }
    Ok(())
}

fn get_pod(options: &KubernetesSourceOptions) -> Result<Pod> {
    let mut command = kubectl(options);
    command.args(["get", "pod", &options.pod, "--output", "json"]);
    let output = checked_output(command, "read source Pod")?;
    serde_json::from_slice(&output.stdout).context("kubectl returned invalid source Pod JSON")
}

fn select_container<'a>(pod: &'a Pod, requested: Option<&str>) -> Result<&'a PodContainer> {
    if let Some(requested) = requested {
        return pod
            .spec
            .containers
            .iter()
            .find(|container| container.name == requested)
            .with_context(|| format!("source Pod has no regular container {requested:?}"));
    }
    ensure!(
        pod.spec.containers.len() == 1,
        "source Pod has {} regular containers; --pod-container is required",
        pod.spec.containers.len()
    );
    Ok(&pod.spec.containers[0])
}

fn select_status<'a>(pod: &'a Pod, container: &str) -> Result<&'a PodContainerStatus> {
    pod.status
        .container_statuses
        .iter()
        .find(|status| status.name == container)
        .with_context(|| format!("source Pod has no runtime status for container {container:?}"))
}

fn normalize_registry_digest(image_id: &str) -> Result<String> {
    let image_id = image_id
        .strip_prefix("docker-pullable://")
        .unwrap_or(image_id);
    ensure!(
        image_id.rsplit_once("@sha256:").is_some_and(
            |(_, digest)| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
        ),
        "source Pod imageID must contain an immutable registry digest, got {image_id:?}"
    );
    Ok(image_id.to_string())
}

fn resolve_image(
    reference: &str,
    registry_digest: &str,
) -> Result<(SourceImage, DockerImageConfig)> {
    let mut output = docker_inspect(registry_digest)?;
    if !output.status.success() {
        let pull = Command::new("docker")
            .args(["pull", "--platform", "linux/amd64", registry_digest])
            .stdin(Stdio::null())
            .output()
            .context("failed to pull source Pod image")?;
        ensure!(
            pull.status.success(),
            "failed to pull source Pod image {registry_digest}: {}",
            String::from_utf8_lossy(&pull.stderr).trim()
        );
        output = docker_inspect(registry_digest)?;
    }
    ensure!(
        output.status.success(),
        "source Pod image {registry_digest} is unavailable to Docker: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut inspections: Vec<DockerImageInspection> = serde_json::from_slice(&output.stdout)
        .context("Docker returned invalid source image inspection JSON")?;
    ensure!(
        inspections.len() == 1,
        "Docker returned an invalid source image inspection"
    );
    let inspection = inspections.remove(0);
    ensure!(
        inspection.id.starts_with("sha256:") && inspection.id.len() == 71,
        "Docker returned an invalid source image ID"
    );
    ensure!(
        inspection.os == "linux" && inspection.architecture == "amd64",
        "source image must be linux/amd64, got {}/{}",
        inspection.os,
        inspection.architecture
    );
    Ok((
        SourceImage {
            reference: reference.to_string(),
            registry_digest: Some(registry_digest.to_string()),
            archive_sha256: None,
            local_id: inspection.id,
            architecture: inspection.architecture,
            os: inspection.os,
        },
        inspection.config,
    ))
}

fn docker_inspect(image: &str) -> Result<Output> {
    Command::new("docker")
        .args(["image", "inspect", image])
        .stdin(Stdio::null())
        .output()
        .context("failed to inspect source Pod image")
}

fn read_effective_environment(
    options: &KubernetesSourceOptions,
    container: &str,
) -> Result<BTreeMap<String, String>> {
    let mut command = kubectl(options);
    command
        .args([
            "exec",
            &options.pod,
            "--container",
            container,
            "--",
            "env",
            "-0",
        ])
        .stdin(Stdio::inherit());
    let output = checked_output(command, "read effective source container environment")?;
    ensure!(
        output.stdout.len() <= MAX_SOURCE_ENVIRONMENT_BYTES,
        "effective source environment exceeds {} bytes",
        MAX_SOURCE_ENVIRONMENT_BYTES
    );
    let mut environment = BTreeMap::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = String::from_utf8(entry.to_vec())
            .context("effective source environment is not UTF-8")?;
        let (name, value) = entry
            .split_once('=')
            .context("effective source environment contains an entry without '='")?;
        validate_environment_name(name)?;
        ensure!(
            environment
                .insert(name.to_string(), value.to_string())
                .is_none(),
            "effective source environment declares {name:?} more than once"
        );
    }
    ensure!(
        environment.len() <= MAX_SOURCE_ENVIRONMENT_VARIABLES,
        "effective source environment exceeds {MAX_SOURCE_ENVIRONMENT_VARIABLES} variables"
    );
    Ok(environment)
}

fn target_environment_names(
    container: &PodContainer,
    image: &DockerImageConfig,
    environment: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in image.env.as_deref().unwrap_or_default() {
        if let Some((name, _)) = entry.split_once('=')
            && is_target_environment_name(name)
        {
            names.insert(name.to_string());
        }
    }
    for entry in &container.env {
        let application_owned = entry.value.is_some()
            || entry.value_from.as_ref().is_some_and(|source| {
                source.config_map_key_ref.is_some() || source.secret_key_ref.is_some()
            });
        if application_owned && is_target_environment_name(&entry.name) {
            names.insert(entry.name.clone());
        }
        if entry
            .value_from
            .as_ref()
            .is_some_and(|source| source.field_ref.is_some() || source.resource_field_ref.is_some())
        {
            names.remove(&entry.name);
        }
    }
    for source in &container.env_from {
        let prefix = source.prefix.as_deref().unwrap_or_default();
        match (&source.config_map_ref, &source.secret_ref) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => anyhow::bail!("source Pod envFrom must reference exactly one ConfigMap or Secret"),
        }
        // The effective container environment is authoritative even when an
        // admission-time ConfigMap or Secret is no longer API-readable.
        infer_environment_from(prefix, environment, &mut names);
    }
    for entry in &container.env {
        if entry
            .value_from
            .as_ref()
            .is_some_and(|source| source.field_ref.is_some() || source.resource_field_ref.is_some())
        {
            names.remove(&entry.name);
        }
    }
    names.retain(|name| {
        environment.get(name).is_some_and(|value| {
            !value.contains(['\0', '\r', '\n']) && is_target_environment_name(name)
        })
    });
    Ok(names)
}

fn infer_environment_from(
    prefix: &str,
    environment: &BTreeMap<String, String>,
    names: &mut BTreeSet<String>,
) {
    names.extend(
        environment
            .keys()
            .filter(|name| {
                (prefix.is_empty() || name.starts_with(prefix))
                    && is_target_environment_name(name)
                    && !is_kubernetes_service_environment(name, environment)
            })
            .cloned(),
    );
}

fn is_kubernetes_service_environment(name: &str, environment: &BTreeMap<String, String>) -> bool {
    if name == "KUBERNETES_PORT"
        || name.starts_with("KUBERNETES_PORT_")
        || name == "KUBERNETES_SERVICE_HOST"
        || name.starts_with("KUBERNETES_SERVICE_PORT")
    {
        return true;
    }
    environment.keys().any(|candidate| {
        candidate
            .strip_suffix("_SERVICE_HOST")
            .is_some_and(|prefix| {
                name == candidate
                    || name == format!("{prefix}_SERVICE_PORT")
                    || name.starts_with(&format!("{prefix}_SERVICE_PORT_"))
                    || name == format!("{prefix}_PORT")
                    || name.starts_with(&format!("{prefix}_PORT_"))
            })
    })
}

fn capture_mounts(
    options: &KubernetesSourceOptions,
    pod: &Pod,
    container: &PodContainer,
    mounts_root: &Path,
) -> Result<(Vec<SourceSnapshotMount>, Vec<SourceIgnoredMount>)> {
    let volumes = pod
        .spec
        .volumes
        .iter()
        .map(|volume| (volume.name.as_str(), volume))
        .collect::<HashMap<_, _>>();
    let mut mounts = Vec::new();
    let mut ignored = Vec::new();
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    for mount in &container.volume_mounts {
        validate_source_mount_path(&mount.mount_path)?;
        ensure!(
            seen_paths.iter().all(|existing| {
                !existing.starts_with(&mount.mount_path) && !mount.mount_path.starts_with(existing)
            }),
            "source mounts overlap at {}",
            mount.mount_path.display()
        );
        seen_paths.push(mount.mount_path.clone());
        let volume = volumes.get(mount.name.as_str()).with_context(|| {
            format!(
                "source Pod mount references missing volume {:?}",
                mount.name
            )
        })?;
        let (kind, reason) = classify_volume(volume, &mount.mount_path);
        match kind {
            VolumeKind::Snapshot => {
                copy_mounted_path(options, &container.name, &mount.mount_path, mounts_root)?;
                mounts.push(SourceSnapshotMount {
                    path: mount.mount_path.clone(),
                    writable: false,
                    projection: SourceMountProjection::Snapshot,
                });
            }
            VolumeKind::Empty => mounts.push(SourceSnapshotMount {
                path: mount.mount_path.clone(),
                writable: !mount.read_only,
                projection: SourceMountProjection::Empty,
            }),
            VolumeKind::Ignored => ignored.push(SourceIgnoredMount {
                path: mount.mount_path.clone(),
                reason,
            }),
        }
    }
    mounts.sort_by(|left, right| left.path.cmp(&right.path));
    ignored.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((mounts, ignored))
}

fn classify_volume(volume: &PodVolume, path: &Path) -> (VolumeKind, String) {
    if volume.config_map.is_some() || volume.secret.is_some() {
        return (VolumeKind::Snapshot, String::new());
    }
    if let Some(projected) = &volume.projected {
        let supported = !projected.sources.is_empty()
            && projected
                .sources
                .iter()
                .all(|source| source.get("configMap").is_some() || source.get("secret").is_some());
        return if supported {
            (VolumeKind::Snapshot, String::new())
        } else {
            (
                VolumeKind::Ignored,
                "projected volume contains a source other than ConfigMap or Secret".to_string(),
            )
        };
    }
    if volume.host_path.is_some() {
        return if is_virtual_system_path(path) {
            (
                VolumeKind::Ignored,
                "virtual /proc, /sys, or /dev hostPath".to_string(),
            )
        } else {
            (
                VolumeKind::Empty,
                "hostPath content is not captured".to_string(),
            )
        };
    }
    if volume.persistent_volume_claim.is_some() {
        return (
            VolumeKind::Ignored,
            "PVC content is not supported".to_string(),
        );
    }
    if volume.empty_dir.is_some() {
        return (
            VolumeKind::Ignored,
            "emptyDir content is not captured".to_string(),
        );
    }
    (
        VolumeKind::Ignored,
        "unsupported Kubernetes volume type".to_string(),
    )
}

fn copy_mounted_path(
    options: &KubernetesSourceOptions,
    container: &str,
    path: &Path,
    mounts_root: &Path,
) -> Result<()> {
    let relative = path.strip_prefix("/").expect("validated absolute mount");
    let destination = mounts_root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let source = format!("{}:{}", options.pod, path.display());
    let mut command = kubectl(options);
    command
        .args(["cp", "--container", container, &source])
        .arg(&destination);
    checked_output(command, &format!("copy source mount {}", path.display()))?;
    ensure!(
        fs::symlink_metadata(&destination).is_ok(),
        "kubectl did not copy source mount {}",
        path.display()
    );
    Ok(())
}

fn validate_source_mount_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path != Path::new("/"),
        "invalid source mount path"
    );
    ensure!(
        path.components().all(|component| matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "source mount path must be normalized: {}",
        path.display()
    );
    ensure!(
        !path
            .to_string_lossy()
            .contains(['\0', '\r', '\n', '\t', ',', ':']),
        "source mount path contains an unsupported delimiter"
    );
    Ok(())
}

fn is_virtual_system_path(path: &Path) -> bool {
    ["/proc", "/sys", "/dev"]
        .iter()
        .map(Path::new)
        .any(|reserved| path == reserved || path.starts_with(reserved))
}

fn kubectl(options: &KubernetesSourceOptions) -> Command {
    let mut command = Command::new(&options.kubectl_binary);
    if let Some(kubeconfig) = &options.kubeconfig {
        command.arg("--kubeconfig").arg(kubeconfig);
    }
    if let Some(context) = &options.context {
        command.args(["--context", context]);
    }
    command.args(["--namespace", &options.namespace]);
    command
}

fn checked_output(mut command: Command, label: &str) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("failed to execute kubectl to {label}"))?;
    ensure!(
        output.stdout.len() <= MAX_KUBECTL_OUTPUT_BYTES
            && output.stderr.len() <= MAX_KUBECTL_OUTPUT_BYTES,
        "kubectl output is too large while trying to {label}"
    );
    ensure!(
        output.status.success(),
        "failed to {label}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kubernetes_image_id_acronym() {
        let status: PodContainerStatus = serde_json::from_value(serde_json::json!({
            "name": "app",
            "imageID": "docker-pullable://registry.example/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ready": true,
            "restartCount": 3,
            "state": { "running": { "startedAt": "2026-09-04T00:00:00Z" } }
        }))
        .unwrap();
        assert_eq!(status.restart_count, 3);
        assert!(status.image_id.starts_with("docker-pullable://"));
    }

    #[test]
    fn accepts_registry_digest_and_rejects_runtime_only_image_id() {
        assert_eq!(
            normalize_registry_digest(
                "docker-pullable://registry.example/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .unwrap(),
            "registry.example/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert!(
            normalize_registry_digest(
                "containerd://sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
    }

    #[test]
    fn projected_volume_support_is_limited_to_config_and_secret() {
        let supported = PodVolume {
            name: "config".to_string(),
            config_map: None,
            secret: None,
            projected: Some(ProjectedVolume {
                sources: vec![
                    serde_json::json!({"configMap": {"name": "one"}}),
                    serde_json::json!({"secret": {"name": "two"}}),
                ],
            }),
            host_path: None,
            persistent_volume_claim: None,
            empty_dir: None,
        };
        assert_eq!(
            classify_volume(&supported, Path::new("/etc/app")).0,
            VolumeKind::Snapshot
        );

        let token = PodVolume {
            projected: Some(ProjectedVolume {
                sources: vec![serde_json::json!({"serviceAccountToken": {"path": "token"}})],
            }),
            ..supported
        };
        assert_eq!(
            classify_volume(&token, Path::new("/var/run/secrets")).0,
            VolumeKind::Ignored
        );
    }

    #[test]
    fn host_paths_become_empty_runtime_mounts_except_virtual_files() {
        let volume = PodVolume {
            name: "logs".to_string(),
            config_map: None,
            secret: None,
            projected: None,
            host_path: Some(serde_json::json!({"path": "/data/logs"})),
            persistent_volume_claim: None,
            empty_dir: None,
        };
        assert_eq!(
            classify_volume(&volume, Path::new("/data/logs")).0,
            VolumeKind::Empty
        );
        assert_eq!(
            classify_volume(&volume, Path::new("/proc/cpuinfo")).0,
            VolumeKind::Ignored
        );
    }

    #[test]
    fn missing_env_from_object_falls_back_to_effective_application_names() {
        let environment = BTreeMap::from([
            ("PORT".to_string(), "8080".to_string()),
            ("DATABASE_URL".to_string(), "mysql://database".to_string()),
            (
                "KUBERNETES_SERVICE_HOST".to_string(),
                "10.0.0.1".to_string(),
            ),
            ("KUBERNETES_SERVICE_PORT".to_string(), "443".to_string()),
            ("REDIS_SERVICE_HOST".to_string(), "10.0.0.2".to_string()),
            ("REDIS_SERVICE_PORT".to_string(), "6379".to_string()),
            ("REDIS_PORT".to_string(), "tcp://10.0.0.2:6379".to_string()),
            ("HOSTNAME".to_string(), "pod-name".to_string()),
        ]);
        let mut names = BTreeSet::new();
        infer_environment_from("", &environment, &mut names);

        assert_eq!(
            names,
            BTreeSet::from(["DATABASE_URL".to_string(), "PORT".to_string()])
        );
    }
}
