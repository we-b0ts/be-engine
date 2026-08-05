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
use crate::request_headers::ENCRYPTION_KEY_ENV;

pub(super) const REPLAY_CA_CERT_ENV: &str = "TRAFFIC_E2E_REPLAY_CA_CERT_PATH";

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

pub(super) async fn run_project(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    args: &[&str],
    evidence_path: &Path,
) -> Result<CommandEvidence> {
    run_project_with_environment(config, layout, args, evidence_path, None).await
}

pub(super) async fn start_project_with_replay_ca(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    evidence_path: &Path,
    replay_ca_cert_path: &Path,
) -> Result<CommandEvidence> {
    let target_boot_dir = config.target_boot_dir.display().to_string();
    let target_port = config.target_port.to_string();
    run_project_with_environment(
        config,
        layout,
        &[
            "start",
            "--e2e",
            "--boot-dir",
            &target_boot_dir,
            "--port",
            &target_port,
        ],
        evidence_path,
        Some(replay_ca_cert_path),
    )
    .await
}

async fn run_project_with_environment(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    args: &[&str],
    evidence_path: &Path,
    replay_ca_cert_path: Option<&Path>,
) -> Result<CommandEvidence> {
    let mut command = Command::new(&config.project_cli);
    command.current_dir(&layout.target_root).args(args);
    sanitize_project_environment(&mut command);
    if let Some(path) = replay_ca_cert_path {
        command.env(REPLAY_CA_CERT_ENV, path);
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

fn sanitize_project_environment(command: &mut Command) {
    for name in PROXY_ENVIRONMENT {
        command.env_remove(name);
    }
    command.env_remove(ENCRYPTION_KEY_ENV);
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
            state.push_error(format!("target cleanup failed: {error:#}"));
        }
        state.target_started = false;
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
    use crate::e2e_run::model::{ResolvedProjectConfig, RunLayout};
    use std::fs;
    use std::time::Duration;

    fn resolved_project(project_cli: PathBuf) -> ResolvedProjectConfig {
        ResolvedProjectConfig {
            project_cli,
            target_boot_dir: PathBuf::from(crate::repository::LOCAL_BOOT_ROOT),
            target_http_origin: "http://127.0.0.1:8081".to_string(),
            target_port: 8081,
            target_readiness_path: "/healthz".to_string(),
            target_readiness_status: 404,
            target_startup_timeout: Duration::from_secs(1),
            target_request_timeout: Duration::from_secs(1),
            target_max_response_bytes: 1024,
            source_container: "source".to_string(),
            breeze_container: Some("breeze".to_string()),
            replay_policy: PathBuf::from("/target/config/replay.yaml"),
            replay_startup_timeout: Duration::from_secs(1),
            pr_base: "dev-migration".to_string(),
            recorder_config: "recorder.toml".into(),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn replay_ca_environment_is_explicit_and_absent_from_evidence() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let project_cli = directory.path().join("project-cli");
        fs::write(
            &project_cli,
            format!("#!/bin/sh\nprintf '%s' \"${{{REPLAY_CA_CERT_ENV}:-unset}}\"\n"),
        )
        .unwrap();
        let mut permissions = fs::metadata(&project_cli).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&project_cli, permissions).unwrap();
        let mut config = resolved_project(project_cli);
        config.replay_policy = directory.path().join("verification.yaml");
        let layout = RunLayout {
            target_root: directory.path().to_path_buf(),
            run_key: "run".to_string(),
            case_source: directory.path().join("cases"),
            progress_path: directory.path().join("progress.yaml"),
            legacy_progress_path: directory.path().join("legacy-progress.yaml"),
            internal_root: directory.path().join("internal"),
            current_path: directory.path().join("current.yaml"),
            run_root: directory.path().join("run"),
            index_path: directory.path().join("index.yaml"),
            group_index_path: directory.path().join("groups.json"),
            active_dir: directory.path().join("active"),
            latest_dir: directory.path().join("latest"),
        };
        fs::create_dir_all(&layout.active_dir).unwrap();
        let ca_cert = directory.path().join("replay-ca.pem");
        fs::write(&ca_cert, "certificate").unwrap();

        let ordinary = run_project(
            &config,
            &layout,
            &["status"],
            &directory.path().join("ordinary.json"),
        )
        .await
        .unwrap();
        assert_eq!(ordinary.stdout, "unset");

        let start = start_project_with_replay_ca(
            &config,
            &layout,
            &directory.path().join("start.json"),
            &ca_cert,
        )
        .await
        .unwrap();
        assert_eq!(start.stdout, ca_cert.display().to_string());
        let evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.path().join("start.json")).unwrap())
                .unwrap();
        let command = evidence.pointer("/command").unwrap().to_string();
        assert!(!command.contains(REPLAY_CA_CERT_ENV));
        assert!(!command.contains(&ca_cert.display().to_string()));
        assert_eq!(
            evidence["command"],
            serde_json::json!([
                config.project_cli.display().to_string(),
                "start",
                "--e2e",
                "--boot-dir",
                ".traffic-e2e/local/boot",
                "--port",
                "8081"
            ])
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
        let mut config = resolved_project(PathBuf::from("/target/scripts/project"));
        config.replay_startup_timeout = Duration::from_secs(60);
        config.pr_base = "integration".to_string();
        config.recorder_config = PathBuf::from("/target/config/recorder.toml");
        config.recording_rule = "pluto".to_string();
        config.runner_owned_response_assertions = false;

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

    #[test]
    fn project_commands_do_not_receive_request_header_encryption_keys() {
        let mut command = Command::new("true");
        command.env(ENCRYPTION_KEY_ENV, "test-secret");

        sanitize_project_environment(&mut command);

        assert!(
            command
                .as_std()
                .get_envs()
                .any(|(name, value)| { name == ENCRYPTION_KEY_ENV && value.is_none() })
        );
    }
}
