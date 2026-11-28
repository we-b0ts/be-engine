use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tokio::process::Command;

use super::NETWORK_ANCHOR_IMAGE;

const PREPARE_TIMEOUT: Duration = Duration::from_secs(60);
const CONTAINER_ROOT: &str = "/workspace/runtime-outputs";

pub(super) async fn prepare(
    root: &Path,
    configs: &[crate::runtime_output::RuntimeOutputConfig],
) -> Result<Vec<crate::RuntimeOutputLocation>> {
    if configs.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        root.is_absolute(),
        "target runtime output root must be absolute: {}",
        root.display()
    );
    let parent = root
        .parent()
        .context("target runtime output root has no parent")?;
    tokio::fs::create_dir_all(parent).await.with_context(|| {
        format!(
            "failed to create target runtime output parent {}",
            parent.display()
        )
    })?;
    tokio::fs::create_dir(root).await.with_context(|| {
        format!(
            "target runtime output root already exists or cannot be created: {}",
            root.display()
        )
    })?;
    tokio::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .await
        .with_context(|| {
            format!(
                "failed to protect target runtime output root {}",
                root.display()
            )
        })?;

    let host_uid = tokio::fs::symlink_metadata(root)
        .await
        .with_context(|| {
            format!(
                "failed to inspect target runtime output root {}",
                root.display()
            )
        })?
        .uid();
    let mut command = helper_command(root)?;
    command.args([
        "-ec",
        "owner=$1; output_root=$2; shift 2; for id do mkdir \"$output_root/$id\"; chown \"$owner:998\" \"$output_root/$id\"; chmod 2770 \"$output_root/$id\"; done",
        "sh",
        &host_uid.to_string(),
        CONTAINER_ROOT,
    ]);
    for config in configs {
        command.arg(&config.id);
    }
    let output = tokio::time::timeout(PREPARE_TIMEOUT, command.output())
        .await
        .context("timed out preparing target runtime outputs")?
        .context("failed to launch target runtime output helper")?;
    if !output.status.success() {
        let _ = tokio::fs::remove_dir_all(root).await;
        anyhow::bail!(
            "failed to prepare target runtime outputs: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(crate::runtime_output::locations(root, "target", configs))
}

fn helper_command(root: &Path) -> Result<Command> {
    let source = root
        .to_str()
        .context("target runtime output root is not UTF-8")?;
    ensure!(
        !source.contains([',', '\r', '\n']),
        "target runtime output root contains an unsupported delimiter"
    );
    let mut command = Command::new("docker");
    command
        .args([
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
            &format!("type=bind,source={source},target={CONTAINER_ROOT}"),
        ])
        .arg(NETWORK_ANCHOR_IMAGE)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_mounts_only_the_engine_owned_output_root() {
        let command =
            helper_command(Path::new("/repo/.traffic-e2e/local/runtime-outputs/run")).unwrap();
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(arguments.contains(&"--network".to_string()));
        assert!(arguments.contains(&"none".to_string()));
        assert!(arguments.contains(&format!(
            "type=bind,source=/repo/.traffic-e2e/local/runtime-outputs/run,target={CONTAINER_ROOT}"
        )));
    }
}
