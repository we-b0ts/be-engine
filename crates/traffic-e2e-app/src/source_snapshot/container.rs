use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use super::{
    CapturedSource, ContainerSourceOptions, SourceIgnoredMount, SourceImage, SourceMountProjection,
    SourceProviderEvidence, SourceRuntime, SourceSecurityContext, SourceSnapshotMount,
    validate_environment_name, validate_snapshot_mount_path,
};

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspection {
    id: String,
    name: String,
    image: String,
    restart_count: u32,
    state: ContainerState,
    config: ContainerConfig,
    host_config: HostConfig,
    mounts: Vec<Mount>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    status: String,
    running: bool,
    paused: bool,
    restarting: bool,
    dead: bool,
    started_at: String,
    finished_at: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(default)]
    image: String,
    env: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    user: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    privileged: bool,
    readonly_rootfs: bool,
    cap_add: Option<Vec<String>>,
    cap_drop: Option<Vec<String>>,
    security_opt: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(rename = "Type")]
    kind: String,
    source: Option<String>,
    destination: PathBuf,
    #[serde(rename = "RW")]
    writable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageInspection {
    id: String,
    architecture: String,
    os: String,
    config: ContainerConfig,
}

pub(super) fn capture(
    options: &ContainerSourceOptions,
    mounts_root: &Path,
) -> Result<CapturedSource> {
    let reference = &options.container;
    ensure!(
        !reference.is_empty()
            && reference == reference.trim()
            && !reference.starts_with('-')
            && !reference.contains(['\0', '\r', '\n', ':']),
        "source container must be a name or ID"
    );
    let before = inspect_container(reference)?;
    validate_container(&before)?;
    let source_image = inspect_image(&before.image)?;
    ensure!(
        source_image.os == "linux" && source_image.architecture == "amd64",
        "source image must be linux/amd64, got {}/{}",
        source_image.os,
        source_image.architecture
    );
    let environment = environment(&before.config)?;
    let target_environment = environment
        .iter()
        .filter(|(name, value)| {
            super::environment::is_target_environment_name(name)
                && !value.contains(['\0', '\r', '\n'])
        })
        .map(|(name, _)| name.clone())
        .collect();
    let security = security(&before.host_config)?;
    validate_mounts(&before.mounts)?;
    let (mounts, ignored_mounts) = capture_mounts(&before, mounts_root)?;

    // Commit retains the writable layer and the container's effective image
    // configuration, including cleared ENTRYPOINT and overridden WORKDIR/CMD.
    // Do not pause or start the user's source container during initialization.
    let output = docker(
        &["container", "commit", "--pause=false", &before.id],
        "snapshot source container filesystem",
    )?;
    let committed_id = committed_image_id(&output.stdout)?;
    let result = (|| {
        let committed = inspect_image(&committed_id)?;
        ensure!(
            committed.id == committed_id,
            "Docker returned a different source snapshot image"
        );
        let after = inspect_container(&before.id)?;
        ensure!(
            before == after,
            "source container changed while its runtime snapshot was being captured; retry initialization"
        );
        let archive_sha256 = super::image::save_archive(
            &committed_id,
            mounts_root
                .parent()
                .context("source staging root is missing")?,
        )?;
        Ok(CapturedSource {
            provider: SourceProviderEvidence::DockerContainer {
                container: before.name.trim_start_matches('/').to_string(),
                container_id: before.id.clone(),
                source_image_id: before.image.clone(),
                restart_count: before.restart_count,
            },
            image: SourceImage {
                reference: before.config.image.clone(),
                registry_digest: None,
                local_id: committed_id.clone(),
                architecture: committed.architecture,
                os: committed.os,
                archive_sha256: Some(archive_sha256),
            },
            runtime: SourceRuntime {
                image_entrypoint: committed.config.entrypoint.unwrap_or_default(),
                image_command: committed.config.cmd.unwrap_or_default(),
                working_directory: nonempty(committed.config.working_dir),
                image_user: nonempty(committed.config.user),
                pod_command: None,
                pod_args: None,
                security,
                environment,
                target_environment,
            },
            mounts,
            ignored_mounts,
        })
    })();
    if result.is_err() {
        // This ID was created by this capture, never the input container/image.
        super::image::remove_captured_image(&committed_id);
    }
    result
}

fn validate_container(container: &ContainerInspection) -> Result<()> {
    ensure!(
        container.id.len() == 64
            && container.id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !container.name.trim_start_matches('/').is_empty()
            && super::image::is_image_id(&container.image),
        "Docker returned invalid source container identity"
    );
    ensure!(
        matches!(
            container.state.status.as_str(),
            "running" | "exited" | "created"
        ) && !container.state.paused
            && !container.state.restarting
            && !container.state.dead,
        "source container must be running, exited, or created; got {}",
        container.state.status
    );
    Ok(())
}

fn committed_image_id(stdout: &[u8]) -> Result<String> {
    // New Docker versions emit a deprecation notice for --pause on stdout.
    // Retain the flag for older Docker versions and parse the terminal ID.
    let text = std::str::from_utf8(stdout).context("Docker returned a non-UTF-8 image ID")?;
    let id = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    ensure!(
        super::image::is_image_id(id),
        "Docker returned an invalid committed image ID"
    );
    Ok(id.to_string())
}

fn inspect_container(reference: &str) -> Result<ContainerInspection> {
    let output = docker(
        &["container", "inspect", reference],
        "inspect source container",
    )?;
    let mut inspections: Vec<ContainerInspection> = serde_json::from_slice(&output.stdout)
        .context("Docker returned invalid source container JSON")?;
    ensure!(
        inspections.len() == 1,
        "Docker must return exactly one source container"
    );
    let mut inspection = inspections.remove(0);
    // Docker emits mounts from an unordered map; order is not a runtime change.
    inspection
        .mounts
        .sort_by(|left, right| left.destination.cmp(&right.destination));
    Ok(inspection)
}

fn inspect_image(reference: &str) -> Result<ImageInspection> {
    let output = docker(
        &["image", "inspect", reference],
        "inspect source container image",
    )?;
    let mut inspections: Vec<ImageInspection> = serde_json::from_slice(&output.stdout)
        .context("Docker returned invalid source image JSON")?;
    ensure!(
        inspections.len() == 1,
        "Docker must return exactly one source image"
    );
    Ok(inspections.remove(0))
}

fn environment(config: &ContainerConfig) -> Result<BTreeMap<String, String>> {
    let entries = config.env.as_deref().unwrap_or_default();
    ensure!(
        entries.len() <= 4096 && entries.iter().map(String::len).sum::<usize>() <= 8 * 1024 * 1024,
        "source container environment is too large"
    );
    let mut values = BTreeMap::new();
    for entry in entries {
        let (name, value) = entry
            .split_once('=')
            .context("source environment entry has no '='")?;
        validate_environment_name(name)?;
        ensure!(!value.contains('\0'), "source environment contains NUL");
        ensure!(
            values.insert(name.to_string(), value.to_string()).is_none(),
            "source environment declares {name:?} more than once"
        );
    }
    Ok(values)
}

fn security(config: &HostConfig) -> Result<SourceSecurityContext> {
    let mut no_new_privileges = false;
    for option in config.security_opt.as_deref().unwrap_or_default() {
        match option.as_str() {
            "no-new-privileges" | "no-new-privileges:true" | "no-new-privileges=true" => {
                no_new_privileges = true
            }
            _ => anyhow::bail!("unsupported source container security option {option:?}"),
        }
    }
    Ok(SourceSecurityContext {
        privileged: config.privileged,
        read_only_root_filesystem: config.readonly_rootfs,
        no_new_privileges,
        capability_add: config.cap_add.clone().unwrap_or_default(),
        capability_drop: config.cap_drop.clone().unwrap_or_default(),
    })
}

fn validate_mounts(mounts: &[Mount]) -> Result<()> {
    for (index, mount) in mounts.iter().enumerate() {
        validate_snapshot_mount_path(&mount.destination)?;
        ensure!(
            mounts.iter().skip(index + 1).all(|other| {
                !mount.destination.starts_with(&other.destination)
                    && !other.destination.starts_with(&mount.destination)
            }),
            "source mounts overlap at {}",
            mount.destination.display()
        );
    }
    Ok(())
}

fn capture_mounts(
    container: &ContainerInspection,
    mounts_root: &Path,
) -> Result<(Vec<SourceSnapshotMount>, Vec<SourceIgnoredMount>)> {
    let mut mounts = Vec::new();
    let mut ignored = Vec::new();
    for mount in &container.mounts {
        let path = &mount.destination;
        let virtual_path = ["/proc", "/sys", "/dev"]
            .iter()
            .any(|root| path.starts_with(root));
        let network_path = ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"]
            .iter()
            .any(|root| path == Path::new(root));
        if virtual_path
            || network_path
            || !matches!(mount.kind.as_str(), "bind" | "volume" | "tmpfs")
        {
            ignored.push(SourceIgnoredMount {
                path: path.clone(),
                reason: "runtime-owned path or unsupported Docker mount type".to_string(),
            });
            continue;
        }
        if mount.kind == "tmpfs" {
            mounts.push(SourceSnapshotMount {
                path: path.clone(),
                writable: mount.writable,
                projection: SourceMountProjection::Empty,
            });
            continue;
        }
        let destination = mounts_root.join(path.strip_prefix("/")?);
        fs::create_dir_all(
            destination
                .parent()
                .context("source mount parent is missing")?,
        )?;
        let source = format!("{}:{}", container.id, path.display());
        let output = Command::new("docker")
            .args(["cp", "--follow-link", &source])
            .arg(&destination)
            .stdin(Stdio::null())
            .output()
            .context("failed to copy source container mount")?;
        ensure!(
            output.status.success(),
            "failed to copy source container mount {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        ensure!(
            destination.exists(),
            "Docker did not copy source mount {}",
            path.display()
        );
        mounts.push(SourceSnapshotMount {
            path: path.clone(),
            writable: mount.writable,
            projection: SourceMountProjection::Snapshot,
        });
    }
    mounts.sort_by(|a, b| a.path.cmp(&b.path));
    ignored.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((mounts, ignored))
}

fn docker(args: &[&str], label: &str) -> Result<Output> {
    let output = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to {label}"))?;
    ensure!(
        output.stdout.len() <= 16 * 1024 * 1024 && output.stderr.len() <= 16 * 1024 * 1024,
        "Docker output is too large while trying to {label}"
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
#[path = "container_tests.rs"]
mod tests;
