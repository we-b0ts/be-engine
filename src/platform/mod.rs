use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde::Serialize;
use tokio::process::Command;
use uuid::Uuid;

use crate::e2e_run::resolve_project;
use crate::recording_api::RecordingApi;

mod preflight;
mod recording_input;
mod recovery;

pub use preflight::{
    ManagedRecordingPreflightOptions, ManagedRecordingPreflightRecordingResult,
    ManagedRecordingPreflightResult,
};
pub use recording_input::{
    ManagedRecordingInputOptions, ManagedRecordingInputResult, drive_managed_recording_input,
};
pub use recovery::{ManagedRecordingRecoveryResult, recover_managed_recording};

const MANAGER: &str = include_str!("assets/manage-platform.sh");
const BREEZE_NO_FALLBACK: &str = include_str!("assets/brz-no-fallback.sh");
const HTTPS_PROBE: &[u8] = include_bytes!("assets/HttpsProbe.class");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedRecordingOperation {
    Record,
    RecordComparison,
}

impl ManagedRecordingOperation {
    pub(crate) fn script_name(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::RecordComparison => "record-comparison",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedRuntimeOperation {
    Recording(ManagedRecordingOperation),
    Preflight,
}

impl ManagedRuntimeOperation {
    fn script_name(self) -> &'static str {
        match self {
            Self::Recording(operation) => operation.script_name(),
            Self::Preflight => "preflight",
        }
    }

    fn manifest(self, target_root: &Path, run_id: &str) -> PathBuf {
        match self {
            Self::Recording(ManagedRecordingOperation::Record) => target_root
                .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
                .join("recordings")
                .join(run_id)
                .join("recording-run.json"),
            Self::Recording(ManagedRecordingOperation::RecordComparison) => target_root
                .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
                .join("comparison-recordings")
                .join(run_id)
                .join("comparison-recording-run.json"),
            Self::Preflight => target_root
                .join(crate::repository::LOCAL_ROOT)
                .join("preflight")
                .join(run_id)
                .join("artifacts/recordings")
                .join(run_id)
                .join("recording-run.json"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedRecordingOptions {
    pub target_root: PathBuf,
    pub operation: ManagedRecordingOperation,
    pub run_id: Option<String>,
    pub duration_seconds: NonZeroU64,
    pub baseline_recheck: bool,
    pub breeze_no_fallback: bool,
    pub apis: Vec<RecordingApi>,
    pub per_api_case_limit: Option<NonZeroUsize>,
    pub request_source: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedRecordingResult {
    pub operation: ManagedRecordingOperation,
    pub run_id: String,
    pub target_root: PathBuf,
    pub source_container: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breeze_container: Option<String>,
    pub manifest: PathBuf,
    pub managed_by: &'static str,
}

struct ManagedRuntimeResult {
    run_id: String,
    target_root: PathBuf,
    source_container: String,
    breeze_container: Option<String>,
    manifest: PathBuf,
}

pub async fn run_managed_recording(
    options: ManagedRecordingOptions,
) -> Result<ManagedRecordingResult> {
    ensure!(
        options.operation == ManagedRecordingOperation::RecordComparison
            || !options.baseline_recheck,
        "--baseline-recheck is valid only for record-comparison"
    );
    let operation = options.operation;
    let result =
        run_managed_runtime(options, ManagedRuntimeOperation::Recording(operation)).await?;
    Ok(ManagedRecordingResult {
        operation,
        run_id: result.run_id,
        target_root: result.target_root,
        source_container: result.source_container,
        breeze_container: result.breeze_container,
        manifest: result.manifest,
        managed_by: "traffic-e2e",
    })
}

pub async fn run_managed_recording_preflight(
    options: ManagedRecordingPreflightOptions,
) -> Result<ManagedRecordingPreflightResult> {
    let (target_root, project) = resolve_project(&options.target_root)?;
    let target_container = crate::target_container::run_preflight(
        crate::target_container::TargetContainerConfig::from_project(target_root.clone(), &project),
    )
    .await
    .context("target_container preflight failed")?;
    let runtime = run_managed_runtime(
        ManagedRecordingOptions {
            target_root,
            operation: ManagedRecordingOperation::Record,
            run_id: None,
            duration_seconds: options.duration_seconds,
            baseline_recheck: false,
            breeze_no_fallback: options.breeze_no_fallback,
            apis: options.apis,
            per_api_case_limit: options.per_api_case_limit,
            request_source: None,
        },
        ManagedRuntimeOperation::Preflight,
    )
    .await?;
    let evidence = preflight::validate(&runtime.manifest)?;
    Ok(ManagedRecordingPreflightResult {
        status: "passed",
        target_container,
        recording: ManagedRecordingPreflightRecordingResult {
            status: "passed",
            run_id: runtime.run_id,
            target_root: runtime.target_root,
            source_container: runtime.source_container,
            breeze_container: runtime.breeze_container,
            manifest: runtime.manifest,
            published_cases: evidence.published_cases,
            https_interception_verified: evidence.https_interception_verified,
        },
        managed_by: "traffic-e2e",
    })
}

async fn run_managed_runtime(
    options: ManagedRecordingOptions,
    runtime_operation: ManagedRuntimeOperation,
) -> Result<ManagedRuntimeResult> {
    let (target_root, config) = resolve_project(&options.target_root)?;
    let run_id = options
        .run_id
        .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    let manifest = runtime_operation.manifest(&target_root, &run_id);
    let target_image = if runtime_operation
        == ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
    {
        crate::target_container::prepare_boot_dir(&config.target_boot_dir).await?;
        Some(
            crate::target_container::build_image(
                &crate::target_container::TargetContainerConfig::from_project(
                    target_root.clone(),
                    &config,
                ),
            )
            .await?,
        )
    } else {
        None
    };
    let recorder_config = &config.recorder_config;
    ensure!(
        recorder_config.is_file(),
        "recorder config does not exist: {}",
        recorder_config.display()
    );
    let recorder = crate::config::AppConfig::load_comparison_recording(recorder_config)?;
    ensure!(
        recorder.http_gateway.ready.enabled,
        "managed recording requires an enabled http_gateway.ready probe"
    );
    let comparison = recorder
        .comparison_recording
        .as_ref()
        .context("managed recording requires comparison configuration")?;
    let source_origin = comparison
        .baseline_upstream(&recorder.http_gateway)
        .to_string();
    let recording_origin = format!("http://127.0.0.1:{}", recorder.http_gateway.listen.port());
    let request_source = options
        .request_source
        .map(fs::canonicalize)
        .transpose()
        .context("failed to resolve managed recording request source")?;
    if let Some(request_source) = &request_source {
        ensure!(
            request_source.starts_with(target_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT)),
            "managed recording request source must be under {}",
            crate::repository::LOCAL_ARTIFACTS_ROOT
        );
    }
    let executable = crate::engine_binary::executable()?;
    ensure_executable(&executable, "traffic-e2e binary")?;
    let assets = stage_assets(&target_root)?;
    let mut command = Command::new("bash");
    command
        .arg(assets.join("manage-platform.sh"))
        .arg(runtime_operation.script_name())
        .current_dir(&target_root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .env("TRAFFIC_E2E_BIN", executable)
        .env("TRAFFIC_E2E_TARGET_ROOT", &target_root)
        .env("TRAFFIC_E2E_SOURCE_CONTAINER", &config.source_container)
        .env("TRAFFIC_E2E_TARGET_BOOT_DIR", &config.target_boot_dir)
        .env("TRAFFIC_E2E_TARGET_ORIGIN", &config.target_http_origin)
        .env("TRAFFIC_E2E_TARGET_PORT", config.target_port.to_string())
        .env(
            "TRAFFIC_E2E_TARGET_READY_PATH",
            &config.target_readiness_path,
        )
        .env(
            "TRAFFIC_E2E_TARGET_READY_STATUS",
            config.target_readiness_status.to_string(),
        )
        .env(
            "TRAFFIC_E2E_TARGET_STARTUP_TIMEOUT_SECONDS",
            config.target_startup_timeout.as_secs().to_string(),
        )
        .env("TRAFFIC_E2E_SOURCE_ORIGIN", source_origin)
        .env("TRAFFIC_E2E_RECORDING_ORIGIN", recording_origin)
        .env(
            "TRAFFIC_E2E_SOURCE_READY_PATH",
            &recorder.http_gateway.ready.path,
        )
        .env(
            "TRAFFIC_E2E_SOURCE_READY_STATUS",
            recorder.http_gateway.ready.success_status.to_string(),
        )
        .env("TRAFFIC_E2E_RECORDER_CONFIG", recorder_config)
        .env("TRAFFIC_E2E_REPLAY_POLICY", &config.replay_policy)
        .env("TRAFFIC_E2E_PLATFORM_ASSETS", &assets)
        .arg("--duration-seconds")
        .arg(options.duration_seconds.to_string())
        .arg("--run-id")
        .arg(&run_id)
        .arg("--brz-no-fallback")
        .arg(options.breeze_no_fallback.to_string());
    if let Some(image) = target_image {
        command.env("TRAFFIC_E2E_TARGET_IMAGE_ID", image.id);
    }
    if let Some(request_source) = request_source {
        command.env("TRAFFIC_E2E_REQUEST_SOURCE", request_source);
    }
    if let Some(container) = &config.breeze_container {
        command.env("TRAFFIC_E2E_BREEZE_CONTAINER", container);
    }
    if options.baseline_recheck {
        command.arg("--baseline-recheck");
    }
    for api in &options.apis {
        command.arg("--api").arg(api.to_string());
    }
    if let Some(limit) = options.per_api_case_limit {
        command.arg("--per-api-case-limit").arg(limit.to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_dir_all(&assets);
            return Err(error).context("failed to start managed recording runtime");
        }
    };
    let status = wait_for_managed_runtime(&mut child).await;
    let asset_cleanup = fs::remove_dir_all(&assets)
        .with_context(|| format!("failed to remove managed assets {}", assets.display()));
    let status = status?;
    ensure!(
        status.success(),
        "managed recording runtime exited with {status}"
    );
    asset_cleanup?;
    Ok(ManagedRuntimeResult {
        run_id,
        target_root,
        source_container: config.source_container,
        breeze_container: config.breeze_container,
        manifest,
    })
}

async fn wait_for_managed_runtime(
    child: &mut tokio::process::Child,
) -> Result<std::process::ExitStatus> {
    tokio::select! {
        status = child.wait() => status.context("failed to wait for managed recording runtime"),
        signal = shutdown_signal() => {
            signal?;
            #[cfg(unix)]
            signal_process_group(child, libc::SIGTERM);
            #[cfg(not(unix))]
            child.start_kill().context("failed to stop managed recording runtime")?;
            match tokio::time::timeout(std::time::Duration::from_secs(180), child.wait()).await {
                Ok(status) => status.context("failed to wait for managed recording cleanup"),
                Err(_) => {
                    #[cfg(unix)]
                    signal_process_group(child, libc::SIGKILL);
                    let _ = child.kill().await;
                    anyhow::bail!("managed recording runtime did not clean up after termination")
                }
            }
        }
    }
}

pub(super) async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(unix)]
fn signal_process_group(child: &tokio::process::Child, signal: libc::c_int) {
    if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

fn stage_assets(target_root: &Path) -> Result<PathBuf> {
    let root = crate::internal_runtime::root(target_root)
        .join("platform/assets")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create Platform asset root {}", root.display()))?;
    write_asset(&root.join("manage-platform.sh"), MANAGER, 0o700)?;
    write_asset(&root.join("brz-no-fallback.sh"), BREEZE_NO_FALLBACK, 0o700)?;
    write_binary_asset(&root.join("HttpsProbe.class"), HTTPS_PROBE, 0o644)?;
    Ok(root)
}

fn write_asset(path: &Path, content: &str, mode: u32) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

fn write_binary_asset(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

fn ensure_executable(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "{label} is not executable: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command as StdCommand;

    use super::*;

    #[test]
    fn embedded_platform_manager_is_valid_bash() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("manage-platform.sh");
        write_asset(&script, MANAGER, 0o700).unwrap();

        let status = StdCommand::new("bash")
            .arg("-n")
            .arg(script)
            .status()
            .unwrap();

        assert!(status.success());
        assert!(MANAGER.contains("start_target()"));
        assert!(MANAGER.contains("--network \"container:${anchor_name}\" --user 998:998"));
        assert!(MANAGER.contains("TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config"));
        assert!(MANAGER.contains("\"$TRAFFIC_E2E_TARGET_IMAGE_ID\" >/dev/null"));
        assert!(!MANAGER.contains("TRAFFIC_E2E_PROJECT_CLI"));
        assert!(!MANAGER.contains("start --e2e"));
        assert!(MANAGER.contains(
            "adapter_dockerfile=\"$TRAFFIC_E2E_TARGET_ROOT/.traffic-e2e/Dockerfile.recording\""
        ));
        assert!(MANAGER.contains("--build-arg \"SOURCE_IMAGE=${source_image_id}\""));
        assert!(MANAGER.contains("find . -mindepth 1 -maxdepth 1 -type f -print0"));
        assert!(MANAGER.contains("--file Dockerfile.recording -"));
        assert!(!MANAGER.contains("MeshConnectUtil.class"));
        assert!(MANAGER.contains(
            "recording_image_project=$(printf '%s' \"$repo_name\" | tr '[:upper:]' '[:lower:]')"
        ));
        assert!(
            MANAGER.contains(
                "adapter_image=\"traffic-e2e/${recording_image_project}-recording:cache\""
            )
        );
        assert!(MANAGER.contains("build_recording_adapter"));
        assert!(MANAGER.contains("resolve_or_build_recording_adapter"));
        assert!(MANAGER.contains("require_initialized_recording_adapter"));
        assert!(MANAGER.contains("reusing initialized recording source image"));
        assert!(MANAGER.contains("initialization must build recording source image"));
        assert!(MANAGER.contains("is missing; building it once"));
        assert!(!MANAGER.contains("recording-adapter.fingerprint"));
        assert!(MANAGER.contains("--iidfile \"$adapter_iid_file\""));
        assert!(
            MANAGER.contains("load_runtime_spec \"$source_inspect\" recording recording image")
        );
        assert!(MANAGER.contains("\"${runtime_args[@]}\" \"$adapter_image_id\" >/dev/null"));
        let adapted_source = MANAGER
            .split_once("start_recording_source()")
            .unwrap()
            .1
            .split_once("run_no_fallback()")
            .unwrap()
            .0;
        assert!(!adapted_source.contains("--user"));
        assert!(!adapted_source.contains("--privileged"));
        assert!(MANAGER.contains(
            "docker run --rm --platform linux/amd64 --network none --user 0:0 --entrypoint /bin/sh"
        ));
        assert!(!MANAGER.contains("cat >\"$adapter_context/Dockerfile\""));
        assert!(!MANAGER.contains("apply-breeze-sdk-patch"));
        assert!(!MANAGER.contains("TRAFFIC_E2E_SOURCE_RUN_COMMAND"));
        assert!(!MANAGER.contains("docker image rm \"$adapter_image\""));
        assert!(MANAGER.contains("[[ \"$operation\" == preflight ]]"));
        assert!(MANAGER.contains(
            "registry.api.demo.test/weibo_rd_if/breeze:v0.1.21-e2e@sha256:5aba065755724d43c7da3f6b79ac82890a0a0a08c6ae3f43af12558b5e52462f"
        ));
        assert!(MANAGER.contains("internal recorder-run --config"));
        assert!(MANAGER.contains("internal comparison-run --config"));
        assert!(MANAGER.contains("record|record-comparison|preflight"));
        assert!(MANAGER.contains("preflight_root=\"$runtime_root/preflight/$run_id\""));
        assert!(MANAGER.contains("[[ \"$operation\" == preflight ]]"));
        assert!(MANAGER.contains("manifest_filter+=' and .published_cases > 0'"));
        assert!(MANAGER.contains("run_preflight_https_probe"));
        assert!(MANAGER.contains("recorder_command+=(--full-traffic-jsonl)"));
        assert!(MANAGER.contains(
            "$TRAFFIC_E2E_PLATFORM_ASSETS/HttpsProbe.class:/traffic-e2e/HttpsProbe.class:ro"
        ));
        assert!(MANAGER.contains("java -Djava.net.preferIPv4Stack=true -cp /traffic-e2e"));
        assert!(!MANAGER.contains("command -v javac"));
        assert!(!MANAGER.contains("getent ahostsv4 demo.test"));
        assert!(MANAGER.contains("phase: \"preflight-business-input-required\""));
        assert!(MANAGER.contains("wait_for_recorder_or_duration"));
        assert!(
            MANAGER.contains(
                "timeout --foreground \"$duration_seconds\" docker wait \"$recorder_name\""
            )
        );
        assert!(!MANAGER.contains("sleep \"$duration_seconds\""));
    }

    #[test]
    fn stages_private_executable_assets() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path();
        let assets = stage_assets(target).unwrap();

        assert_eq!(
            fs::metadata(assets.join("manage-platform.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(assets.join("brz-no-fallback.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(assets.join("HttpsProbe.class"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(&HTTPS_PROBE[..4], b"\xca\xfe\xba\xbe");
        assert_eq!(u16::from_be_bytes([HTTPS_PROBE[6], HTTPS_PROBE[7]]), 52);
        assert!(!assets.join("MeshConnectUtil.java").exists());
        assert!(!assets.join("apply-breeze-sdk-patch").exists());
    }
}
