use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use anyhow::{Context, Result, ensure};
use tokio::process::Command;

use super::NETWORK_ANCHOR_IMAGE;
use crate::startup::StartupSnapshotMount;

const COPY_TIMEOUT: Duration = Duration::from_secs(60);
const SNAPSHOT_ROOT: &str = "/workspace/startup";
const RUNTIME_ROOT: &str = "/workspace/runtime";

pub(super) struct PreparedStartupMount {
    pub(super) source: PathBuf,
    pub(super) target: PathBuf,
    pub(super) writable: bool,
}

pub(super) async fn prepare(
    target_root: &Path,
    container: &str,
    mounts: &[StartupSnapshotMount],
) -> Result<Vec<PreparedStartupMount>> {
    let runtime_root = runtime_mount_root(target_root, container);
    let writable = mounts
        .iter()
        .filter(|mount| mount.writable)
        .collect::<Vec<_>>();
    if !writable.is_empty() {
        let parent = runtime_root
            .parent()
            .expect("target runtime mount root has a parent");
        tokio::fs::create_dir_all(parent).await.with_context(|| {
            format!(
                "failed to create target runtime mount parent {}",
                parent.display()
            )
        })?;
        tokio::fs::create_dir(&runtime_root)
            .await
            .with_context(|| {
                format!(
                    "target runtime mount root already exists or cannot be created: {}",
                    runtime_root.display()
                )
            })?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| {
                format!(
                    "failed to protect target runtime mount root {}",
                    runtime_root.display()
                )
            })?;
        if let Err(error) = copy_writable_mounts(target_root, &runtime_root, &writable).await {
            let _ = cleanup(target_root, container).await;
            return Err(error);
        }
    }

    mounts
        .iter()
        .map(|mount| {
            let source = if mount.writable {
                runtime_root.join(relative_path(&mount.path)?)
            } else {
                crate::startup::startup_mount_source(target_root, &mount.path)?
            };
            Ok(PreparedStartupMount {
                source,
                target: mount.path.clone(),
                writable: mount.writable,
            })
        })
        .collect()
}

pub(super) async fn cleanup(target_root: &Path, container: &str) -> Result<()> {
    let runtime_root = runtime_mount_root(target_root, container);
    let metadata = match tokio::fs::symlink_metadata(&runtime_root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect target runtime mount root {}",
                    runtime_root.display()
                )
            });
        }
    };
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "target runtime mount root must be a directory and not a symlink: {}",
        runtime_root.display()
    );
    let parent = runtime_root
        .parent()
        .expect("target runtime mount root has a parent");
    let mut command = helper_command(parent, None)?;
    command
        .args(["-ec", "rm -rf -- \"$1\"", "sh"])
        .arg(format!("{RUNTIME_ROOT}/{container}"));
    let output = tokio::time::timeout(COPY_TIMEOUT, command.output())
        .await
        .context("timed out cleaning target runtime mounts")?
        .context("failed to launch target runtime mount cleanup helper")?;
    ensure!(
        output.status.success(),
        "failed to clean target runtime mounts: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

async fn copy_writable_mounts(
    target_root: &Path,
    runtime_root: &Path,
    mounts: &[&StartupSnapshotMount],
) -> Result<()> {
    let startup_root = target_root.join(crate::repository::LOCAL_STARTUP_MOUNTS_ROOT);
    let mut command = helper_command(runtime_root, Some(&startup_root))?;
    command.args([
        "-ec",
        "for relative do mkdir -p \"$2/$(dirname \"$relative\")\"; cp --archive --reflink=auto -- \"$1/$relative\" \"$2/$relative\"; done",
        "sh",
        SNAPSHOT_ROOT,
        RUNTIME_ROOT,
    ]);
    for mount in mounts {
        command.arg(relative_text(&mount.path)?);
    }
    let output = tokio::time::timeout(COPY_TIMEOUT, command.output())
        .await
        .context("timed out copying writable startup mounts")?
        .context("failed to launch writable startup mount copy helper")?;
    ensure!(
        output.status.success(),
        "failed to copy writable startup mounts: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn helper_command(runtime_source: &Path, startup_source: Option<&Path>) -> Result<Command> {
    let mut command = Command::new("docker");
    command.args([
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--user",
        "0:0",
        "--entrypoint",
        "/bin/sh",
        "--mount",
        &bind_spec(runtime_source, RUNTIME_ROOT, false)?,
    ]);
    if let Some(startup_source) = startup_source {
        command.args(["--mount", &bind_spec(startup_source, SNAPSHOT_ROOT, true)?]);
    }
    command
        .arg(NETWORK_ANCHOR_IMAGE)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    Ok(command)
}

fn bind_spec(source: &Path, target: &str, read_only: bool) -> Result<String> {
    let source = source
        .to_str()
        .context("target runtime mount source path is not UTF-8")?;
    ensure!(
        !source.contains([',', '\r', '\n']),
        "target runtime mount source contains an unsupported delimiter"
    );
    Ok(format!(
        "type=bind,source={source},target={target}{}",
        if read_only { ",readonly" } else { "" }
    ))
}

fn runtime_mount_root(target_root: &Path, container: &str) -> PathBuf {
    crate::internal_runtime::root(target_root)
        .join("target-container/mounts")
        .join(container)
}

fn relative_path(path: &Path) -> Result<&Path> {
    path.strip_prefix("/")
        .with_context(|| format!("startup mount is not absolute: {}", path.display()))
}

fn relative_text(path: &Path) -> Result<&str> {
    relative_path(path)?
        .to_str()
        .context("startup mount path is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_mounts_are_scoped_by_container() {
        assert_eq!(
            runtime_mount_root(Path::new("/workspace/service"), "target-one"),
            Path::new(
                "/workspace/service/.traffic-e2e/local/runtime/target-container/mounts/target-one"
            )
        );
    }

    #[test]
    fn bind_specs_preserve_requested_access() {
        assert_eq!(
            bind_spec(Path::new("/tmp/source"), "/workspace/runtime", true).unwrap(),
            "type=bind,source=/tmp/source,target=/workspace/runtime,readonly"
        );
        assert_eq!(
            bind_spec(Path::new("/tmp/source"), "/workspace/runtime", false).unwrap(),
            "type=bind,source=/tmp/source,target=/workspace/runtime"
        );
    }
}
