use std::collections::BTreeSet;
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

pub(super) async fn replay_startup_failure(
    layout: &RunLayout,
    status: std::process::ExitStatus,
) -> String {
    let path = layout.active_dir.join("reports/replay.stderr.log");
    let tail = async {
        let mut file = tokio::fs::File::open(&path).await?;
        let length = file.metadata().await?.len();
        file.seek(SeekFrom::Start(length.saturating_sub(4096)))
            .await?;
        let mut bytes = Vec::new();
        file.take(4096).read_to_end(&mut bytes).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&bytes).trim().to_owned())
    }
    .await;
    let reason = match tail {
        Ok(tail) if !tail.is_empty() => tail,
        Ok(_) => "Replay stderr is empty".into(),
        Err(error) => format!("Replay stderr unavailable: {error}"),
    };
    format!("replay process exited before becoming ready with {status}: {reason}")
}

#[derive(Debug, Serialize)]
struct TargetRuntimeChecks {
    status: &'static str,
    process_identity: bool,
    startup_snapshot: bool,
    startup_environment: bool,
    runtime_mount_access: bool,
    listen_all_interfaces: bool,
    readiness: bool,
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
        .arg(&config.replay_policy)
        .arg("--case-dependency-post-response-window-ms")
        .arg(
            config
                .replay_case_dependency_post_response_window
                .as_millis()
                .to_string(),
        )
        .arg("--case-no-progress-timeout-ms")
        .arg(
            config
                .replay_case_no_progress_timeout
                .as_millis()
                .to_string(),
        );
    if config.replay_pre_match {
        command.arg("--pre-match");
    }
    command.args(replay_stream_timing_args(config));
    if config.replay_loading.lazy_cases {
        command.arg("--lazy-case-dependencies");
    }
    command
        .arg("--dependency-cache-bytes")
        .arg(config.replay_loading.cache_bytes.to_string());
    command
        .arg("--case-prepare-timeout-seconds")
        .arg(config.replay_loading.case_timeout_seconds.to_string());
    command.args(recorder_config_args(config));
    command.args(replay_case_args(inventory, state));
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
    ]
}

fn replay_stream_timing_args(config: &ResolvedProjectConfig) -> Vec<OsString> {
    config.replay_stream_timing.map_or_else(Vec::new, |timing| {
        vec![
            "--stream-timing".into(),
            match timing {
                crate::replay::ReplayStreamTiming::Fast => "fast",
                crate::replay::ReplayStreamTiming::Recorded => "recorded",
            }
            .into(),
            "--stream-interval-cap-ms".into(),
            config.replay_stream_interval_cap_ms.to_string().into(),
        ]
    })
}

fn replay_api_args(inventory: &CaseGroupInventory) -> Vec<OsString> {
    inventory
        .groups
        .iter()
        .flat_map(|group| [OsString::from("--api"), OsString::from(&group.group_id)])
        .collect()
}

pub(super) fn replay_case_args(
    inventory: &CaseGroupInventory,
    state: &ActiveRunState,
) -> Vec<OsString> {
    if state
        .case_selection
        .as_ref()
        .is_some_and(|selection| !selection.skipped_passed_case_ids.is_empty())
    {
        state
            .cases
            .iter()
            .flat_map(|case| [OsString::from("--case-id"), OsString::from(&case.case_id)])
            .collect()
    } else {
        replay_api_args(inventory)
    }
}

pub(super) async fn build_target_image(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
) -> Result<crate::TargetImage> {
    let target = crate::target_container::TargetContainerConfig::from_project(
        layout.target_root.clone(),
        config,
    );
    crate::target_container::build_image(&target)
        .await
        .context("target image build failed")
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
    let output_scope = layout
        .run_root
        .strip_prefix(&layout.internal_root)
        .context("E2E run root is outside the internal runtime root")?;
    let runtime_output_root = layout
        .target_root
        .join(crate::repository::LOCAL_RUNTIME_OUTPUTS_ROOT)
        .join("replay")
        .join(output_scope)
        .join(format!("sequence-{:06}", state.sequence))
        .join("target");
    let evidence =
        crate::target_container::start_target(crate::target_container::TargetStartOptions {
            config: &target,
            image,
            container_name,
            network_container: anchor_name,
            operation: "replay",
            run_id: runtime_id,
            replay_ca_cert: Some(replay_ca_cert_path.to_path_buf()),
            runtime_outputs: &config.target_runtime_outputs,
            runtime_output_root,
        })
        .await?;
    state.runtime_outputs = evidence.runtime_outputs.clone();
    for output in &state.runtime_outputs {
        eprintln!(
            "target runtime output {}: {} -> {}",
            output.id,
            output.container_path.display(),
            output.host_path.display()
        );
    }
    store::write_active(layout, state)?;
    store::write_json(
        &layout.active_dir.join("reports/target-start.json"),
        &evidence,
    )?;
    Ok(())
}

pub(super) async fn verify_target_runtime_contract(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &ActiveRunState,
) -> Result<()> {
    let container = state
        .target_container_name
        .as_deref()
        .context("active E2E state has no target container name")?;
    let target = crate::target_container::TargetContainerConfig::from_project(
        layout.target_root.clone(),
        config,
    );
    crate::target_container::verify_target_identity(container).await?;
    crate::target_container::verify_startup_environment(container, &layout.target_root).await?;
    let snapshot = crate::startup::load_startup_snapshot(&layout.target_root, &target.startup)?;
    crate::target_container::verify_runtime_mounts(
        container,
        snapshot.mounts(),
        &config.target_runtime_outputs,
        true,
    )
    .await?;
    if config.target_http_readiness_enabled {
        crate::target_container::verify_listen_address(container, target.port).await?;
    }
    if let Some(upstream) = config.target_motan_upstream.as_deref() {
        let port = crate::platform::endpoint_port(upstream, "target Motan endpoint")?;
        crate::target_container::verify_listen_address(container, port).await?;
    }
    store::write_json(
        &layout.active_dir.join("reports/target-runtime-checks.json"),
        &TargetRuntimeChecks {
            status: "passed",
            process_identity: true,
            startup_snapshot: true,
            startup_environment: true,
            runtime_mount_access: true,
            listen_all_interfaces: true,
            readiness: true,
        },
    )?;
    Ok(())
}

pub(super) async fn stop_target_runtime(
    layout: &RunLayout,
    state: &mut ActiveRunState,
) -> Result<()> {
    stop_target_process(layout, state, true).await
}

pub(super) async fn stop_target_at_case_boundary(
    layout: &RunLayout,
    state: &mut ActiveRunState,
) -> Result<()> {
    stop_target_process(layout, state, false).await
}

async fn stop_target_process(
    layout: &RunLayout,
    state: &mut ActiveRunState,
    require_clean_exit: bool,
) -> Result<()> {
    let container = state
        .target_container_name
        .clone()
        .context("active E2E state has no target container name")?;
    capture_target_diagnostics(layout, state).await;
    let evidence = crate::target_container::stop_target(&layout.target_root, &container).await?;
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
        !require_clean_exit || evidence.exit_code == 0,
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

pub(super) fn validate_replay_case_selection(
    ready: &serde_json::Value,
    state: &ActiveRunState,
) -> Result<()> {
    let selected_values = ready
        .pointer("/session/selected_case_ids")
        .and_then(serde_json::Value::as_array)
        .context("Replay session has no selected_case_ids")?;
    let mut selected = BTreeSet::new();
    for value in selected_values {
        let case_id = value
            .as_str()
            .context("Replay session contains a non-string selected case id")?;
        ensure!(
            selected.insert(case_id),
            "Replay session contains duplicate selected case id {case_id:?}"
        );
    }
    let expected = state
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    if selected != expected {
        let missing = expected
            .difference(&selected)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let unexpected = selected
            .difference(&expected)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "Replay API selection differs from the canonical case inventory: expected {} cases, resolved {}; missing [{}], unexpected [{}]",
            expected.len(),
            selected.len(),
            missing,
            unexpected
        );
    }
    Ok(())
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

pub(super) async fn finalize_replay(
    state: &mut ActiveRunState,
    intentionally_incomplete: bool,
    scope: crate::replay::FinalizationScope,
) -> Result<()> {
    let command = scope.command();
    if intentionally_incomplete {
        let response = control(state, command, None, false, false)
            .await
            .context("failed to finalize intentionally incomplete replay")?;
        state.replay_finalized = response
            .get("finalized")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        return Ok(());
    }
    let response = match control(state, command, None, true, true).await {
        Ok(response) => response,
        Err(strict_error) => {
            state.push_error(format!("strict replay finalize failed: {strict_error:#}"));
            control(state, command, None, false, false)
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
        capture_target_diagnostics(layout, state).await;
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

async fn capture_target_diagnostics(layout: &RunLayout, state: &mut ActiveRunState) {
    let Some(container) = state.target_container_name.as_deref() else {
        return;
    };
    if let Err(error) =
        crate::target_container::capture_diagnostics(container, &layout.active_dir.join("reports"))
            .await
    {
        state.push_error(format!("target diagnostics capture failed: {error:#}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod finalization;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup};
    use crate::e2e_run::model::ResolvedProjectConfig;
    use std::fs;
    use std::time::Duration;

    fn resolved_project(target_dockerfile: PathBuf) -> ResolvedProjectConfig {
        ResolvedProjectConfig {
            replay_case_no_progress_timeout: Duration::from_secs(5),
            replay_pre_match: true,
            replay_stream_timing: None,
            replay_stream_interval_cap_ms: crate::replay::DEFAULT_REPLAY_STREAM_INTERVAL_CAP_MS,
            replay_socketio_timing: Default::default(),
            target_dockerfile,
            target_build_contexts: Vec::new(),
            target_startup: crate::startup::StartupConfig::default(),
            target_runtime_outputs: Vec::new(),
            target_http_origin: "http://127.0.0.1:8081".to_string(),
            target_port: 8081,
            target_http_readiness_enabled: true,
            target_motan_upstream: None,
            target_motan_connect_timeout: Duration::from_secs(1),
            target_motan_request_timeout: Duration::from_secs(1),
            target_motan_limits: motan_protocol::Limits::default(),
            target_readiness_path: "/healthz".to_string(),
            target_readiness_status: 404,
            target_startup_timeout: Duration::from_secs(1),
            target_request_timeout: Duration::from_secs(1),
            target_max_response_bytes: 1024,
            replay_policy: PathBuf::from("/target/config/replay.yaml"),
            replay_case_dependency_post_response_window: Duration::from_millis(10),
            max_failed_cases_per_api: crate::DEFAULT_MAX_FAILED_CASES_PER_API,
            replay_loading: crate::replay::ReplayDependencyLoading::default(),
            replay_startup_timeout: Duration::from_secs(1),
            pr_base: "dev-migration".to_string(),
            quality_check: "cargo-clippy".into(),
            managed_paths: Vec::new(),
            recorder_config: "project.yaml".into(),
            source_traffic_policy: "source-traffic-policy.yaml".into(),
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
        let mut config = resolved_project(PathBuf::from("/target/.traffic-e2e/Dockerfile.target"));
        config.replay_startup_timeout = Duration::from_secs(60);
        config.pr_base = "integration".to_string();
        config.recorder_config = PathBuf::from("/target/config/project.yaml");
        config.runner_owned_response_assertions = false;

        assert_eq!(
            recorder_config_args(&config),
            vec![
                OsString::from("--recorder-config"),
                OsString::from("/target/config/project.yaml"),
            ]
        );
    }

    #[test]
    fn managed_replay_passes_only_explicit_regression_stream_timing() {
        use crate::replay::ReplayStreamTiming::{Fast, Recorded};
        let mut config = resolved_project(PathBuf::from("/target/Dockerfile"));
        assert!(replay_stream_timing_args(&config).is_empty());
        for (mode, value) in [(Fast, "fast"), (Recorded, "recorded")] {
            config.replay_stream_timing = Some(mode);
            assert_eq!(
                replay_stream_timing_args(&config),
                vec![
                    OsString::from("--stream-timing"),
                    OsString::from(value),
                    OsString::from("--stream-interval-cap-ms"),
                    OsString::from("5")
                ]
            );
        }
        config.replay_stream_interval_cap_ms = 0;
        assert_eq!(replay_stream_timing_args(&config).last().unwrap(), "0");
    }

    #[test]
    fn managed_replay_passes_api_identity_instead_of_expanded_case_ids() {
        let inventory = case_inventory();

        assert_eq!(
            replay_api_args(&inventory),
            vec![
                OsString::from("--api"),
                OsString::from("GET /api/widgets/*"),
            ]
        );
    }

    #[test]
    fn managed_replay_requires_api_selection_to_match_canonical_cases() {
        let inventory = case_inventory();
        let state = ActiveRunState::new("run".to_string(), 1, &inventory, Path::new("/run"));
        validate_replay_case_selection(
            &serde_json::json!({
                "session": {"selected_case_ids": ["case-a", "case-b"]}
            }),
            &state,
        )
        .unwrap();

        let error = validate_replay_case_selection(
            &serde_json::json!({
                "session": {"selected_case_ids": ["case-a"]}
            }),
            &state,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("expected 2 cases, resolved 1"));
        assert!(error.contains("missing [case-b]"));
    }

    fn case_inventory() -> CaseGroupInventory {
        CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api/widgets/*".to_string(),
                method: "GET".to_string(),
                source_route: "/api/widgets/:id".to_string(),
                pattern: Some("/api/widgets/*".to_string()),
                case_inventory_id: "widgets".to_string(),
                cases: vec![
                    CanonicalCase {
                        case_id: "case-a".to_string(),
                        case_dir: PathBuf::from("/cases/alpha/case-a"),
                        recorded_at: None,
                    },
                    CanonicalCase {
                        case_id: "case-b".to_string(),
                        case_dir: PathBuf::from("/cases/beta/case-b"),
                        recorded_at: None,
                    },
                ],
            }],
        }
    }
}
