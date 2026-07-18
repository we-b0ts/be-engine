use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
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
    let replay_command = std::env::var_os("TRAFFIC_E2E_TRAFFIC_REPLAY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("traffic-replay"));
    let stdout = File::create(layout.active_dir.join("reports/replay.stdout.log"))?;
    let stderr = File::create(layout.active_dir.join("reports/replay.stderr.log"))?;
    let mut command = Command::new(&replay_command);
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
    })
    .await
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
    fn standard_runner_passes_recorder_config_and_rule_to_replay() {
        let config = ResolvedProjectConfig {
            project_cli: PathBuf::from("/target/scripts/project"),
            replay_policy: PathBuf::from("/target/config/replay.yaml"),
            pr_base: "integration".to_string(),
            recorder_config: Some(PathBuf::from("/target/config/recorder.toml")),
            recording_rule: Some("pluto".to_string()),
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
