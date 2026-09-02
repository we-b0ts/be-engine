use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::process::Command;

use super::build::validate_image_id;
use super::model::{
    TargetRuntimeState, TargetStartEvidence, TargetStartOptions, TargetStopEvidence,
};
use super::{NETWORK_ANCHOR_IMAGE, TARGET_REPLAY_CA_PATH, TARGET_USER};
use super::{runtime_outputs, startup_mounts};
use crate::{TRAFFIC_PROCESS_GID, TRAFFIC_PROCESS_UID, TRAFFIC_PROCESS_USER};

const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_SECONDS: &str = "15";
const MANAGED_LABEL: &str = "com.weibo.traffic-e2e.managed=true";
const BREEZE_CONNECT_HOST_ENVIRONMENT: &str = "MESH_CONNECT_HOST=breeze.recording";
const TARGET_LOG_TAIL_LINES: &str = "2000";
const MAX_TARGET_LOG_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspection {
    state: ContainerState,
    mounts: Vec<ContainerMount>,
    config: ContainerConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    env: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    running: bool,
    exit_code: i64,
    #[serde(rename = "OOMKilled")]
    oom_killed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerMount {
    destination: String,
    #[serde(rename = "RW")]
    rw: bool,
}

pub(crate) fn runtime_name(
    target_root: &Path,
    operation: &str,
    run_id: &str,
    role: &str,
) -> Result<String> {
    let repository = crate::repository::directory_name(target_root)?;
    let raw = format!("traffic-e2e-{repository}-{operation}-{run_id}-{role}");
    let mut normalized = String::with_capacity(raw.len().min(120));
    let mut previous_dash = false;
    for character in raw.chars() {
        let accepted = character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-');
        if accepted {
            normalized.push(character);
            previous_dash = character == '-';
        } else if !previous_dash {
            normalized.push('-');
            previous_dash = true;
        }
        if normalized.len() >= 120 {
            break;
        }
    }
    let normalized = normalized
        .trim_matches(|character| matches!(character, '.' | '_' | '-'))
        .to_string();
    ensure!(!normalized.is_empty(), "target container name is empty");
    Ok(normalized)
}

pub(crate) async fn create_anchor(
    name: &str,
    host_network: bool,
    operation: &str,
    run_id: &str,
) -> Result<()> {
    validate_name(name)?;
    let network = if host_network { "host" } else { "none" };
    let output = docker_output(
        Command::new("docker")
            .args(["run", "--detach", "--name", name])
            .args(["--platform", "linux/amd64", "--network", network])
            .args(["--label", MANAGED_LABEL])
            .args([
                "--label",
                "com.weibo.traffic-e2e.role=target-network-anchor",
            ])
            .args([
                "--label",
                &format!("com.weibo.traffic-e2e.operation={operation}"),
            ])
            .args(["--label", &format!("com.weibo.traffic-e2e.run-id={run_id}")])
            .arg(NETWORK_ANCHOR_IMAGE),
        "start target network anchor",
    )
    .await?;
    ensure!(
        output.status.success(),
        "failed to start target network anchor: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub(crate) async fn start_target(options: TargetStartOptions<'_>) -> Result<TargetStartEvidence> {
    validate_name(&options.container_name)?;
    validate_name(&options.network_container)?;
    validate_image_id(&options.image.id)?;
    let snapshot = crate::startup::load_startup_snapshot(
        &options.config.target_root,
        &options.config.startup,
    )?;
    if options.config.breeze_enabled {
        require_breeze_mounts()?;
    }
    let replay_ca_mount = if let Some(ca_cert) = &options.replay_ca_cert {
        require_regular_file(ca_cert, "Replay CA certificate")?;
        Some(bind_mount(ca_cert, TARGET_REPLAY_CA_PATH, false)?)
    } else {
        None
    };
    let environment_file = crate::internal_runtime::root(&options.config.target_root)
        .join("target-container")
        .join(format!("{}.env", options.container_name));
    let has_environment = crate::startup::write_docker_environment_file(
        &environment_file,
        &snapshot,
        &options.config.startup,
        options.config.port,
        options.replay_ca_cert.is_some(),
        TARGET_REPLAY_CA_PATH,
    )?;
    let prepared_mounts = match startup_mounts::prepare(
        &options.config.target_root,
        &options.container_name,
        snapshot.mounts(),
    )
    .await
    {
        Ok(mounts) => mounts,
        Err(error) => {
            if let Err(cleanup) = remove_environment_file(&environment_file, has_environment).await
            {
                return Err(error.context(format!(
                    "target environment cleanup also failed: {cleanup:#}"
                )));
            }
            return Err(error);
        }
    };
    let prepared_outputs =
        match runtime_outputs::prepare(&options.runtime_output_root, options.runtime_outputs).await
        {
            Ok(outputs) => outputs,
            Err(error) => {
                if let Err(cleanup) =
                    startup_mounts::cleanup(&options.config.target_root, &options.container_name)
                        .await
                {
                    return Err(error.context(format!(
                        "target startup mount cleanup also failed: {cleanup:#}"
                    )));
                }
                if let Err(cleanup) =
                    remove_environment_file(&environment_file, has_environment).await
                {
                    return Err(error.context(format!(
                        "target environment cleanup also failed: {cleanup:#}"
                    )));
                }
                return Err(error);
            }
        };

    let mut command = Command::new("docker");
    command
        .args([
            "run",
            "--detach",
            "--name",
            &options.container_name,
            "--platform",
            "linux/amd64",
            "--network",
            &format!("container:{}", options.network_container),
            "--user",
            TARGET_USER,
            "--label",
            MANAGED_LABEL,
            "--label",
            "com.weibo.traffic-e2e.role=target",
            "--label",
            &format!("com.weibo.traffic-e2e.operation={}", options.operation),
            "--label",
            &format!("com.weibo.traffic-e2e.run-id={}", options.run_id),
        ])
        .env_remove(crate::request_headers::ENCRYPTION_KEY_ENV);
    for mount in &prepared_mounts {
        command.args([
            "--mount",
            &bind_mount(
                &mount.source,
                &mount.target.to_string_lossy(),
                mount.writable,
            )?,
        ]);
    }
    for output in &prepared_outputs {
        command.args([
            "--mount",
            &bind_mount(
                &output.host_path,
                &output.container_path.to_string_lossy(),
                true,
            )?,
        ]);
    }
    if options.config.breeze_enabled {
        command
            .args([
                "--mount",
                "type=bind,source=/data1/breeze/socks,target=/data1/breeze/socks,readonly",
            ])
            .args([
                "--mount",
                "type=bind,source=/data1/breeze/snapshot,target=/data1/breeze/snapshot,readonly",
            ]);
    }
    if let Some(replay_ca_mount) = &replay_ca_mount {
        command.args(["--mount", replay_ca_mount]);
    }
    if has_environment {
        command.arg("--env-file").arg(&environment_file);
    }
    if let Some(environment) = breeze_connect_host_environment(options.config.breeze_enabled) {
        command.args(["--env", environment]);
    }
    command.arg(&options.image.id);
    let output = docker_output(&mut command, "start target container").await;
    if let Err(error) = remove_environment_file(&environment_file, has_environment).await {
        let runtime_cleanup = if output.as_ref().is_ok_and(|output| output.status.success()) {
            force_remove_runtime(&options.config.target_root, &[&options.container_name]).await
        } else {
            startup_mounts::cleanup(&options.config.target_root, &options.container_name).await
        };
        if let Err(runtime_cleanup) = runtime_cleanup {
            return Err(error.context(format!(
                "target runtime cleanup also failed: {runtime_cleanup:#}"
            )));
        }
        return Err(error);
    }
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            let cleanup =
                startup_mounts::cleanup(&options.config.target_root, &options.container_name).await;
            let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if let Err(cleanup) = cleanup {
                anyhow::bail!(
                    "failed to start target container: {message}; target startup mount cleanup also failed: {cleanup:#}"
                );
            }
            anyhow::bail!("failed to start target container: {message}");
        }
        Err(error) => {
            if let Err(cleanup) =
                startup_mounts::cleanup(&options.config.target_root, &options.container_name).await
            {
                return Err(error.context(format!(
                    "target startup mount cleanup also failed: {cleanup:#}"
                )));
            }
            return Err(error);
        }
    };
    let container_id = String::from_utf8(output.stdout)
        .context("Docker returned a non-UTF-8 target container ID")?;
    ensure!(
        !container_id.trim().is_empty(),
        "Docker returned an empty target container ID"
    );
    let evidence = TargetStartEvidence {
        status: "started",
        container_name: options.container_name,
        anchor_name: options.network_container,
        image_id: options.image.id.clone(),
        user: TARGET_USER,
        startup_snapshot_id: snapshot.manifest.snapshot_id.clone(),
        startup_mounts: snapshot
            .mounts()
            .iter()
            .map(|mount| mount.path.clone())
            .collect(),
        runtime_outputs: prepared_outputs,
        port: options.config.port,
        replay_ca_cert: options
            .replay_ca_cert
            .as_ref()
            .map(|_| TARGET_REPLAY_CA_PATH),
    };
    Ok(evidence)
}

pub(crate) async fn verify_target_identity(container: &str) -> Result<()> {
    validate_name(container)?;
    let script = format!(
        "test \"$(awk '/^Uid:/{{print $2}}' /proc/1/status)\" = {TRAFFIC_PROCESS_UID}; \
         test \"$(awk '/^Gid:/{{print $2}}' /proc/1/status)\" = {TRAFFIC_PROCESS_GID}"
    );
    let output = docker_output(
        Command::new("docker")
            .args(["exec", container, "/bin/sh", "-ec"])
            .arg(script),
        "verify target process identity",
    )
    .await?;
    ensure!(
        output.status.success(),
        "target process is not running as {TRAFFIC_PROCESS_USER}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub(crate) async fn verify_runtime_mounts(
    container: &str,
    mounts: &[crate::startup::StartupSnapshotMount],
    runtime_outputs: &[crate::runtime_output::RuntimeOutputConfig],
    replay_ca: bool,
    breeze_enabled: bool,
) -> Result<()> {
    let inspection = inspect_container(container).await?;
    ensure!(
        inspection.state.running,
        "target container exited during startup"
    );
    for expected in mounts {
        ensure!(
            inspection.mounts.iter().any(|mount| {
                Path::new(&mount.destination) == expected.path && mount.rw == expected.writable
            }),
            "target startup mount is missing or has the wrong access mode: {} expected {}",
            expected.path.display(),
            if expected.writable { "rw" } else { "ro" }
        );
    }
    for expected in runtime_outputs {
        ensure!(
            inspection.mounts.iter().any(|mount| {
                Path::new(&mount.destination) == expected.container_path && mount.rw
            }),
            "target runtime output mount is missing or read-only: {}",
            expected.container_path.display()
        );
    }
    let managed_read_only_mounts = replay_ca
        .then_some(TARGET_REPLAY_CA_PATH)
        .into_iter()
        .chain(
            breeze_enabled
                .then_some(["/data1/breeze/socks", "/data1/breeze/snapshot"])
                .into_iter()
                .flatten(),
        );
    for expected in managed_read_only_mounts {
        ensure!(
            inspection
                .mounts
                .iter()
                .any(|mount| { Path::new(&mount.destination) == Path::new(expected) && !mount.rw }),
            "target managed mount is missing or writable: {expected}"
        );
    }
    Ok(())
}

pub(crate) async fn verify_startup_environment(
    container: &str,
    config: &crate::startup::StartupConfig,
    replay_ca: bool,
    breeze_enabled: bool,
) -> Result<()> {
    let inspection = inspect_container(container).await?;
    ensure!(
        inspection.config.env.iter().all(|value| {
            value
                .split_once('=')
                .is_none_or(|(name, _)| !name.to_ascii_uppercase().starts_with("TRAFFIC_E2E_"))
        }),
        "target container must not receive traffic-e2e-owned environment variables"
    );
    let mut expected = config.environment_from_source.clone();
    expected.extend(config.port_environment.iter().cloned());
    if replay_ca {
        expected.extend(config.replay_ca_environment.iter().cloned());
    }
    for expected in expected {
        ensure!(
            inspection.config.env.iter().any(|value| {
                value
                    .split_once('=')
                    .is_some_and(|(name, _)| name == expected)
            }),
            "target container is missing configured startup environment {expected:?}"
        );
    }
    if let Some(expected) = breeze_connect_host_environment(breeze_enabled) {
        ensure!(
            inspection.config.env.iter().any(|value| value == expected),
            "Breeze-enabled target container is missing managed environment {expected:?}"
        );
    }
    Ok(())
}

fn breeze_connect_host_environment(enabled: bool) -> Option<&'static str> {
    enabled.then_some(BREEZE_CONNECT_HOST_ENVIRONMENT)
}

pub(crate) async fn verify_listen_address(container: &str, port: u16) -> Result<()> {
    validate_name(container)?;
    let script = format!(
        "port=$(printf '%04X' {port}); awk -v address=00000000:$port '$2 == address && $4 == \"0A\" {{ found=1 }} END {{ exit !found }}' /proc/1/net/tcp"
    );
    let output = docker_output(
        Command::new("docker").args(["exec", container, "/bin/sh", "-ec", &script]),
        "verify target listen address",
    )
    .await?;
    ensure!(
        output.status.success(),
        "target is not listening on 0.0.0.0:{port}"
    );
    Ok(())
}

pub(crate) async fn capture_diagnostics(container: &str, reports_dir: &Path) -> Result<()> {
    validate_name(container)?;
    let output = docker_output(
        Command::new("docker").args([
            "logs",
            "--timestamps",
            "--tail",
            TARGET_LOG_TAIL_LINES,
            container,
        ]),
        "read target logs",
    )
    .await?;
    ensure!(
        output.status.success(),
        "failed to read target logs: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    tokio::fs::write(
        reports_dir.join("target.stdout.log"),
        bounded_log(output.stdout),
    )
    .await
    .context("failed to persist target stdout")?;
    tokio::fs::write(
        reports_dir.join("target.stderr.log"),
        bounded_log(output.stderr),
    )
    .await
    .context("failed to persist target stderr")?;

    let inspection = inspect_container(container).await?;
    let state = TargetRuntimeState {
        running: inspection.state.running,
        exit_code: inspection.state.exit_code,
        oom_killed: inspection.state.oom_killed,
    };
    let mut payload =
        serde_json::to_vec_pretty(&state).context("failed to serialize target runtime state")?;
    payload.push(b'\n');
    tokio::fs::write(reports_dir.join("target-state.json"), payload)
        .await
        .context("failed to persist target runtime state")?;
    Ok(())
}

fn bounded_log(log: Vec<u8>) -> Vec<u8> {
    if log.len() <= MAX_TARGET_LOG_BYTES {
        return log;
    }
    let omitted = log.len() - MAX_TARGET_LOG_BYTES;
    let marker = format!("[traffic-e2e omitted {omitted} earlier log bytes]\n");
    let mut bounded = Vec::with_capacity(marker.len() + MAX_TARGET_LOG_BYTES);
    bounded.extend_from_slice(marker.as_bytes());
    bounded.extend_from_slice(&log[omitted..]);
    bounded
}

pub(crate) async fn stop_target(target_root: &Path, container: &str) -> Result<TargetStopEvidence> {
    validate_name(container)?;
    let output = docker_output(
        Command::new("docker").args(["stop", "--time", STOP_SECONDS, container]),
        "stop target container",
    )
    .await?;
    ensure!(
        output.status.success(),
        "failed to stop target container: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let inspection = inspect_container(container).await?;
    ensure!(
        !inspection.state.running,
        "target container remained running"
    );
    ensure!(
        !inspection.state.oom_killed,
        "target container was OOM-killed"
    );
    let remove = docker_output(
        Command::new("docker").args(["rm", container]),
        "remove target container",
    )
    .await?;
    ensure!(
        remove.status.success(),
        "failed to remove target container: {}",
        String::from_utf8_lossy(&remove.stderr).trim()
    );
    startup_mounts::cleanup(target_root, container).await?;
    Ok(TargetStopEvidence {
        status: if inspection.state.exit_code == 0 {
            "stopped"
        } else {
            "nonzero_exit"
        },
        container_name: container.to_string(),
        exit_code: inspection.state.exit_code,
        removed: true,
    })
}

pub(crate) async fn force_remove_runtime(target_root: &Path, names: &[&str]) -> Result<()> {
    for name in names {
        validate_name(name)?;
        let output = docker_output(
            Command::new("docker").args(["rm", "--force", name]),
            "remove target runtime container",
        )
        .await?;
        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("No such container")
        {
            anyhow::bail!(
                "failed to remove target runtime container {name}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        startup_mounts::cleanup(target_root, name).await?;
    }
    Ok(())
}

async fn inspect_container(name: &str) -> Result<ContainerInspection> {
    validate_name(name)?;
    let output = docker_output(
        Command::new("docker").args(["container", "inspect", name]),
        "inspect target container",
    )
    .await?;
    ensure!(
        output.status.success(),
        "failed to inspect target container: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut values: Vec<ContainerInspection> =
        serde_json::from_slice(&output.stdout).context("Docker returned invalid container JSON")?;
    ensure!(
        values.len() == 1,
        "Docker returned {} target container inspections",
        values.len()
    );
    Ok(values.remove(0))
}

fn require_breeze_mounts() -> Result<()> {
    for path in ["/data1/breeze/socks", "/data1/breeze/snapshot"] {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("required Breeze mount is missing: {path}"))?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "required Breeze mount must be a directory and not a symlink: {path}"
        );
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

async fn remove_environment_file(path: &Path, created: bool) -> Result<()> {
    if !created {
        return Ok(());
    }
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove target environment file {}",
                path.display()
            )
        }),
    }
}

fn bind_mount(source: &Path, target: &str, writable: bool) -> Result<String> {
    let source = source
        .to_str()
        .context("target container mount path is not UTF-8")?;
    ensure!(
        !source
            .chars()
            .any(|character| matches!(character, ',' | '\r' | '\n')),
        "target container mount path contains an unsupported character"
    );
    Ok(format!(
        "type=bind,source={source},target={target}{}",
        if writable { "" } else { ",readonly" }
    ))
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "invalid managed target container name {name:?}"
    );
    Ok(())
}

async fn docker_output(command: &mut Command, action: &str) -> Result<std::process::Output> {
    command.stdin(Stdio::null()).kill_on_drop(true);
    tokio::time::timeout(DOCKER_TIMEOUT, command.output())
        .await
        .with_context(|| format!("timed out while attempting to {action}"))?
        .with_context(|| format!("failed to {action}"))
}

#[cfg(test)]
mod tests;
