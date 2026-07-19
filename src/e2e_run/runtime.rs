use std::ffi::OsString;
use std::fs::File;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::process::{Child, Command};

use super::model::{ActiveRunState, ResolvedProjectConfig, RunLayout};
use super::store;
use super::support::{allocate_control_socket, wait_for_pid_exit};
use crate::case_group::CaseGroupInventory;
use crate::replay::{ReplayControlConfig, run_replay_control};

const PROXY_ENVIRONMENT: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

#[derive(Debug, Serialize)]
pub(super) struct CommandEvidence {
    pub(super) command: Vec<String>,
    pub(super) exit_code: Option<i32>,
    pub(super) success: bool,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) fn spawn_replay(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &ActiveRunState,
) -> Result<Child> {
    let replay_override = std::env::var_os("TRAFFIC_E2E_TRAFFIC_REPLAY").map(PathBuf::from);
    let replay_command = match replay_override.as_ref() {
        Some(command) => command.clone(),
        None => std::env::current_exe().context("failed to resolve traffic-e2e binary")?,
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
    let (Some(recorder_config), Some(recording_rule)) = (
        config.recorder_config.as_ref(),
        config.recording_rule.as_ref(),
    ) else {
        return Vec::new();
    };
    vec![
        OsString::from("--recorder-config"),
        recorder_config.as_os_str().to_owned(),
        OsString::from("--recording-rule"),
        OsString::from(recording_rule),
    ]
}

pub(super) async fn run_project(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    args: &[&str],
    evidence_path: &Path,
) -> Result<CommandEvidence> {
    let mut command = Command::new(&config.project_cli);
    command.current_dir(&layout.target_root).args(args);
    for name in PROXY_ENVIRONMENT {
        command.env_remove(name);
    }
    let output = command.output().await.with_context(|| {
        format!(
            "failed to run project CLI {} {}",
            config.project_cli.display(),
            args.join(" ")
        )
    })?;
    let evidence = CommandEvidence {
        command: std::iter::once(config.project_cli.display().to_string())
            .chain(args.iter().map(|value| (*value).to_string()))
            .collect(),
        exit_code: output.status.code(),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    store::write_json(evidence_path, &evidence)?;
    Ok(evidence)
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
            state
                .errors
                .push(format!("strict replay finalize failed: {strict_error:#}"));
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
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
) {
    if state.target_started {
        if let Err(error) = run_project(
            config,
            layout,
            &["stop"],
            &layout.active_dir.join("reports/target-stop-recovery.json"),
        )
        .await
        {
            state
                .errors
                .push(format!("target cleanup failed: {error:#}"));
        }
        state.target_started = false;
    }
    let replay_pid = state.replay_pid;
    if replay_pid.is_some()
        && state.replay_session.is_file()
        && let Err(error) = control(state, "stop", None, false, false).await
    {
        state
            .errors
            .push(format!("replay cleanup failed: {error:#}"));
    }
    if let Some(pid) = replay_pid {
        wait_for_pid_exit(pid).await;
    }
    state.replay_pid = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_startup_progress_filter_only_accepts_dependency_loading() {
        assert!(is_replay_startup_progress(
            "loading replay case dependencies loaded_cases=0 total_cases=418"
        ));
        assert!(!is_replay_startup_progress(
            "local replay owner filter enabled"
        ));
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
        let config = ResolvedProjectConfig {
            project_cli: PathBuf::from("/target/scripts/project"),
            replay_policy: PathBuf::from("/target/config/replay.yaml"),
            replay_startup_timeout: Duration::from_secs(60),
            pr_base: "integration".to_string(),
            recorder_config: Some(PathBuf::from("/target/config/recorder.toml")),
            recording_rule: Some("pluto".to_string()),
            api_verification: super::super::model::ApiVerificationConfig::default(),
            runner_owned_response_assertions: false,
        };

        assert_eq!(
            recorder_config_args(&config),
            vec![
                OsString::from("--recorder-config"),
                OsString::from("/target/config/recorder.toml"),
                OsString::from("--recording-rule"),
                OsString::from("pluto"),
            ]
        );
    }
}
