use std::ffi::OsString;
use std::fs::File;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::process::{Child, Command};
use uuid::Uuid;

use super::model::{ActiveRunState, ResolvedProjectConfig, RunLayout};
use super::store;
use super::support::wait_for_pid_exit;
use crate::case_group::CaseGroupInventory;
use crate::replay::{ReplayControlConfig, allocate_control_socket, run_replay_control};

const REPLAY_TARGET_HOST_NETWORK: bool = true;
const _: () = assert!(
    REPLAY_TARGET_HOST_NETWORK,
    "Replay target must retain the host namespace used by fake-IP interception"
);

pub(super) fn spawn_replay(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &ActiveRunState,
) -> Result<Child> {
    let replay_override = std::env::var_os("TRAFFIC_E2E_TRAFFIC_REPLAY").map(PathBuf::from);
    let replay_command = match replay_override.as_ref() {
        Some(command) => command.clone(),
        None => crate::engine_binary::executable()?,
    };
    let stdout = File::create(layout.active_dir.join("reports/replay.stdout.log"))?;
    let stderr = File::create(layout.active_dir.join("reports/replay.stderr.log"))?;
    let mut command = Command::new(&replay_command);
    if replay_override.is_none() {
        command.arg("replay");
    }
    command
        .current_dir(&layout.target_root)
        .arg("--report")
        .arg(&state.replay_report)
        .arg("--session")
        .arg(&state.replay_session)
        .arg("--control-socket")
        .arg(allocate_control_socket())
        .arg("--policy")
        .arg(&config.replay_policy);
    command.args(recorder_config_args(config));
    for case_id in inventory
        .groups
        .iter()
        .flat_map(|group| group.cases.iter().map(|case| &case.case_id))
    {
        command.arg("--case-id").arg(case_id);
    }
    command
        .arg(&layout.case_source)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    command
        .spawn()
        .with_context(|| format!("failed to start {}", replay_command.display()))
}

fn recorder_config_args(config: &ResolvedProjectConfig) -> Vec<OsString> {
    vec![
        OsString::from("--recorder-config"),
        config.recorder_config.as_os_str().to_owned(),
        OsString::from("--recording-rule"),
        OsString::from(&config.recording_rule),
    ]
}

pub(super) async fn build_target_image(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
) -> Result<crate::TargetImage> {
    let target = crate::target_container::TargetContainerConfig::from_project(
        layout.target_root.clone(),
        config,
    );
    crate::target_container::build_image(&target).await
}

pub(super) async fn start_target_with_replay_ca(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
    image: &crate::TargetImage,
    replay_ca_cert_path: &Path,
) -> Result<()> {
    let runtime_id = Uuid::new_v4().simple().to_string();
    let anchor_name = crate::target_container::runtime_name(
        &layout.target_root,
        "replay",
        &runtime_id,
        "anchor",
    )?;
    let container_name = crate::target_container::runtime_name(
        &layout.target_root,
        "replay",
        &runtime_id,
        "target",
    )?;
    state.target_started = true;
    state.target_anchor_name = Some(anchor_name.clone());
    state.target_container_name = Some(container_name.clone());
    state.target_image_id = Some(image.id.clone());
    store::write_active(layout, state)?;

    crate::target_container::create_anchor(
        &anchor_name,
        REPLAY_TARGET_HOST_NETWORK,
        "replay",
        &runtime_id,
    )
    .await?;
    let target = crate::target_container::TargetContainerConfig::from_project(
        layout.target_root.clone(),
        config,
    );
    let evidence =
        crate::target_container::start_target(crate::target_container::TargetStartOptions {
            config: &target,
            image,
            container_name,
            network_container: anchor_name,
            operation: "replay",
            run_id: runtime_id,
            replay_ca_cert: Some(replay_ca_cert_path.to_path_buf()),
        })
        .await?;
    store::write_json(
        &layout.active_dir.join("reports/target-start.json"),
        &evidence,
    )?;
    Ok(())
}

pub(super) async fn stop_target_runtime(
    layout: &RunLayout,
    state: &mut ActiveRunState,
) -> Result<()> {
    let container = state
        .target_container_name
        .as_deref()
        .context("active E2E state has no target container name")?;
    let evidence = crate::target_container::stop_target(&layout.target_root, container).await?;
    store::write_json(
        &layout.active_dir.join("reports/target-stop.json"),
        &evidence,
    )?;
    state.target_started = false;
    state.target_container_name = None;
    if let Some(anchor) = state.target_anchor_name.clone() {
        crate::target_container::force_remove_runtime(&layout.target_root, &[&anchor]).await?;
        state.target_anchor_name = None;
    }
    ensure!(
        evidence.exit_code == 0,
        "target exited with {} after SIGTERM",
        evidence.exit_code
    );
    Ok(())
}

pub(super) fn replay_ca_cert_path(ready: &serde_json::Value) -> Result<PathBuf> {
    let value = ready
        .pointer("/session/ca_cert_path")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("replay_capability_gap: replay readiness has no CA certificate path")?;
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute(),
        "replay_capability_gap: replay CA certificate path is not absolute: {}",
        path.display()
    );
    let metadata = std::fs::metadata(&path).with_context(|| {
        format!(
            "replay_capability_gap: failed to inspect replay CA certificate {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.is_file(),
        "replay_capability_gap: replay CA certificate is not a regular file: {}",
        path.display()
    );
    Ok(path)
}

pub(super) async fn control(
    state: &ActiveRunState,
    command: &str,
    case_id: Option<&str>,
    fail_on_dirty: bool,
    fail_on_incomplete: bool,
) -> Result<serde_json::Value> {
    run_replay_control(ReplayControlConfig {
        session_path: state.replay_session.clone(),
        command: command.to_string(),
        case_id: case_id.map(ToOwned::to_owned),
        fail_on_dirty,
        fail_on_incomplete,
        wait_timeout: None,
    })
    .await
}

pub(super) async fn wait_for_replay_ready(
    state: &ActiveRunState,
    timeout: Duration,
) -> Result<serde_json::Value> {
    let wait = run_replay_control(ReplayControlConfig {
        session_path: state.replay_session.clone(),
        command: "wait_ready".to_string(),
        case_id: None,
        fail_on_dirty: false,
        fail_on_incomplete: false,
        wait_timeout: Some(timeout),
    });
    tokio::pin!(wait);
    let progress_path = state
        .replay_report
        .parent()
        .context("replay report has no parent directory")?
        .join("replay.stderr.log");
    let mut progress_offset = 0;
    let mut progress_pending = Vec::new();
    let mut progress_poll = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            result = &mut wait => {
                relay_replay_startup_progress(
                    &progress_path,
                    &mut progress_offset,
                    &mut progress_pending,
                ).await;
                return result;
            }
            _ = progress_poll.tick() => {
                relay_replay_startup_progress(
                    &progress_path,
                    &mut progress_offset,
                    &mut progress_pending,
                ).await;
            }
        }
    }
}

async fn relay_replay_startup_progress(path: &Path, offset: &mut u64, pending: &mut Vec<u8>) {
    if let Err(error) = try_relay_replay_startup_progress(path, offset, pending).await {
        tracing::warn!(
            path = %path.display(),
            error = %error,
            "failed to relay replay startup progress"
        );
    }
}

async fn try_relay_replay_startup_progress(
    path: &Path,
    offset: &mut u64,
    pending: &mut Vec<u8>,
) -> Result<()> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read replay log {}", path.display()));
        }
    };
    file.seek(SeekFrom::Start(*offset)).await?;
    let bytes_read = file.read_to_end(pending).await?;
    *offset = offset.saturating_add(bytes_read as u64);

    let completed_bytes = pending
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    if completed_bytes == 0 {
        return Ok(());
    }
    let completed = pending.drain(..completed_bytes).collect::<Vec<_>>();
    for line in String::from_utf8_lossy(&completed).lines() {
        if is_replay_startup_progress(line) {
            tracing::info!(replay_progress = line, "replay startup progress");
        }
    }
    Ok(())
}

fn is_replay_startup_progress(line: &str) -> bool {
    line.contains("loading replay case dependencies")
}

pub(super) async fn finalize_replay(state: &mut ActiveRunState) -> Result<()> {
    let response = match control(state, "finalize", None, true, true).await {
        Ok(response) => response,
        Err(strict_error) => {
            state.push_error(format!("strict replay finalize failed: {strict_error:#}"));
            control(state, "finalize", None, false, false)
                .await
                .context("failed to finalize replay after recording dirty evidence")?
        }
    };
    state.replay_finalized = response
        .get("finalized")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(())
}

pub(super) async fn wait_for_replay(replay: &mut Child) -> Result<()> {
    let status = match tokio::time::timeout(Duration::from_secs(30), replay.wait()).await {
        Ok(result) => result?,
        Err(_) => {
            replay.kill().await?;
            bail!("replay process did not stop after finalize");
        }
    };
    ensure!(status.success(), "replay process exited with {status}");
    Ok(())
}

pub(super) async fn stop_replay_process(state: &mut ActiveRunState, replay: &mut Child) {
    if state.replay_session.is_file() {
        let _ = control(state, "stop", None, false, false).await;
    }
    if tokio::time::timeout(Duration::from_secs(10), replay.wait())
        .await
        .is_err()
    {
        #[cfg(unix)]
        terminate_process_group(replay, libc::SIGTERM);
        if tokio::time::timeout(Duration::from_secs(5), replay.wait())
            .await
            .is_err()
        {
            #[cfg(unix)]
            terminate_process_group(replay, libc::SIGKILL);
            let _ = replay.kill().await;
        }
    }
    state.replay_pid = None;
}

#[cfg(unix)]
fn terminate_process_group(replay: &Child, signal: libc::c_int) {
    if let Some(pid) = replay.id().and_then(|pid| i32::try_from(pid).ok()) {
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

pub(super) async fn best_effort_stop(
    _config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
) {
    if state.target_started
        || state.target_container_name.is_some()
        || state.target_anchor_name.is_some()
    {
        let names = [
            state.target_container_name.as_deref(),
            state.target_anchor_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if let Err(error) =
            crate::target_container::force_remove_runtime(&layout.target_root, &names).await
        {
            state.push_error(format!("target cleanup failed: {error:#}"));
        }
        state.target_started = false;
        state.target_container_name = None;
        state.target_anchor_name = None;
    }
    let replay_pid = state.replay_pid;
    if replay_pid.is_some()
        && state.replay_session.is_file()
        && let Err(error) = control(state, "stop", None, false, false).await
    {
        state.push_error(format!("replay cleanup failed: {error:#}"));
    }
    if let Some(pid) = replay_pid {
        wait_for_pid_exit(pid).await;
        if super::support::process_exists(pid) {
            state.push_error(format!(
                "replay cleanup did not terminate process group owned by PID {pid}"
            ));
        }
    }
    state.replay_pid = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e_run::model::ResolvedProjectConfig;
    use std::fs;
    use std::time::Duration;

    fn resolved_project(target_dockerfile: PathBuf) -> ResolvedProjectConfig {
        ResolvedProjectConfig {
            target_dockerfile,
            target_startup: crate::startup::StartupConfig::default(),
            target_http_origin: "http://127.0.0.1:8081".to_string(),
            target_port: 8081,
            target_motan_upstream: None,
            target_readiness_path: "/healthz".to_string(),
            target_readiness_status: 404,
            target_startup_timeout: Duration::from_secs(1),
            target_request_timeout: Duration::from_secs(1),
            target_quality_gates: Vec::new(),
            target_max_response_bytes: 1024,
            source_container: "source".to_string(),
            breeze_container: Some("breeze".to_string()),
            replay_policy: PathBuf::from("/target/config/replay.yaml"),
            replay_startup_timeout: Duration::from_secs(1),
            pr_base: "dev-migration".to_string(),
            recorder_config: "project.yaml".into(),
            coordinator_rules: "coordinator-rules.yaml".into(),
            recording_rule: "record-api".to_string(),
            runner_owned_response_assertions: true,
        }
    }

    #[test]
    fn replay_startup_progress_filter_only_accepts_dependency_loading() {
        assert!(is_replay_startup_progress(
            "loading replay case dependencies loaded_cases=0 total_cases=418"
        ));
        assert!(!is_replay_startup_progress(
            "local replay owner filter enabled"
        ));
    }

    #[test]
    fn replay_ca_path_requires_an_absolute_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory.path().join("replay-ca.pem");
        fs::write(&cert, "certificate").unwrap();

        assert_eq!(
            replay_ca_cert_path(&serde_json::json!({
                "session": {"ca_cert_path": cert}
            }))
            .unwrap(),
            cert
        );
        assert!(
            replay_ca_cert_path(&serde_json::json!({
                "session": {"ca_cert_path": "relative/replay-ca.pem"}
            }))
            .unwrap_err()
            .to_string()
            .contains("not absolute")
        );
        assert!(
            replay_ca_cert_path(&serde_json::json!({"session": {}}))
                .unwrap_err()
                .to_string()
                .contains("replay_capability_gap")
        );
        assert!(
            replay_ca_cert_path(&serde_json::json!({
                "session": {"ca_cert_path": directory.path()}
            }))
            .unwrap_err()
            .to_string()
            .contains("not a regular file")
        );
    }

    #[tokio::test]
    async fn replay_startup_progress_relay_preserves_partial_lines() {
        use std::io::Write;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replay.stderr.log");
        std::fs::write(
            &path,
            b"loading replay case dependencies loaded_cases=0 total_cases=418\npartial",
        )
        .unwrap();
        let mut offset = 0;
        let mut pending = Vec::new();

        try_relay_replay_startup_progress(&path, &mut offset, &mut pending)
            .await
            .unwrap();

        assert_eq!(pending, b"partial");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b" line\n").unwrap();

        try_relay_replay_startup_progress(&path, &mut offset, &mut pending)
            .await
            .unwrap();

        assert!(pending.is_empty());
        assert_eq!(offset, std::fs::metadata(path).unwrap().len());
    }

    #[test]
    fn standard_runner_passes_recorder_config_and_rule_to_replay() {
        let mut config = resolved_project(PathBuf::from("/target/.traffic-e2e/Dockerfile.e2e"));
        config.replay_startup_timeout = Duration::from_secs(60);
        config.pr_base = "integration".to_string();
        config.recorder_config = PathBuf::from("/target/config/project.yaml");
        config.recording_rule = "pluto".to_string();
        config.runner_owned_response_assertions = false;

        assert_eq!(
            recorder_config_args(&config),
            vec![
                OsString::from("--recorder-config"),
                OsString::from("/target/config/project.yaml"),
                OsString::from("--recording-rule"),
                OsString::from("pluto"),
            ]
        );
    }
}
