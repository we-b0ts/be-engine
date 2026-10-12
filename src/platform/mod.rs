use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use tokio::process::Command;

use crate::e2e_run::resolve_project;
use crate::recording_api::RecordingApi;

#[cfg(test)]
mod asset_contract_tests;
mod assets;
#[cfg(test)]
mod container_runtime_tests;
pub(crate) mod encryption_key;
mod listen_preflight;
#[cfg(test)]
mod manager_tests;
#[cfg(test)]
mod mount_tests;
mod preflight;
mod replay_preflight;
mod runtime_outputs;
mod startup;

use assets::{stage_assets, write_asset};

pub use preflight::{
    ManagedRecordingPreflightOptions, ManagedRecordingPreflightRecordingResult,
    ManagedRecordingPreflightResult, ManagedTargetImagePreflightChecks,
    ManagedTargetImagePreflightResult,
};
pub use replay_preflight::{
    ManagedReplayNetworkPreflightResult, ManagedTargetRuntimePreflightChecks,
    ManagedTargetRuntimePreflightResult, ReplayDirectEgressProbeResult, ReplayNegativeProbeResult,
    ReplayPositiveProbeResult,
};
const MANAGER: &str = include_str!("assets/manage-platform.sh");
const CONTAINER_RUNTIME: &str = include_str!("assets/container-runtime.sh");
const RECORDER_RUNTIME: &str = include_str!("assets/recorder-runtime.sh");
const PLATFORM_MOUNTS: &str = include_str!("assets/platform-mounts.sh");
const PREFLIGHT_READINESS: &str = include_str!("assets/preflight-readiness.sh");
const HTTPS_PROBE: &[u8] = include_bytes!("assets/HttpsProbe.class");

#[derive(Debug, Clone)]
struct PreflightRecordingOptions {
    pub target_root: PathBuf,
    pub run_id: Option<String>,
    pub duration_seconds: NonZeroU64,
    pub apis: Vec<RecordingApi>,
    pub per_api_case_limit: Option<NonZeroUsize>,
}

struct ManagedRuntimeResult {
    run_id: String,
    target_root: PathBuf,
    source_snapshot_id: String,
    manifest: PathBuf,
}

pub async fn run_managed_recording_preflight(
    options: ManagedRecordingPreflightOptions,
) -> Result<ManagedRecordingPreflightResult> {
    let (target_root, project) = resolve_project(&options.target_root)?;
    ensure!(
        project.target_http_readiness_enabled,
        "initialization preflight requires enabled HTTP readiness"
    );
    let readiness_api = format!("GET {}", project.target_readiness_path)
        .parse::<RecordingApi>()
        .context("configured readiness path cannot form the initialization recording selector")?;
    crate::startup::load_startup_snapshot(&target_root, &project.target_startup)
        .context("target_image preflight failed")?;
    let target_image = crate::target_container::build_image(
        &crate::target_container::TargetContainerConfig::from_project(
            target_root.clone(),
            &project,
        ),
    )
    .await
    .context("target_image preflight failed")?;
    let runtime = run_managed_runtime(PreflightRecordingOptions {
        target_root,
        run_id: None,
        duration_seconds: options.duration_seconds,
        apis: vec![readiness_api],
        per_api_case_limit: NonZeroUsize::new(1),
    })
    .await?;
    let evidence = preflight::validate(&runtime.manifest, &project.target_readiness_path)?;
    let (replay_network, target_runtime) = replay_preflight::run(
        &runtime.target_root,
        &project,
        &runtime.run_id,
        &runtime.manifest,
        &target_image,
    )
    .await?;
    Ok(ManagedRecordingPreflightResult {
        status: "passed",
        target_image: ManagedTargetImagePreflightResult {
            status: "passed",
            image: target_image,
            checks: ManagedTargetImagePreflightChecks {
                build_contract: true,
                image_contract: true,
                startup_snapshot_contract: true,
            },
        },
        recording: ManagedRecordingPreflightRecordingResult {
            status: "passed",
            run_id: runtime.run_id,
            target_root: runtime.target_root,
            source_snapshot_id: runtime.source_snapshot_id,
            probe_kind: evidence.probe_kind,
            manifest: runtime.manifest,
            published_cases: evidence.published_cases,
            https_interception_verified: evidence.https_interception_verified,
            global_probe_dependency_verified: evidence.global_probe_dependency_verified,
        },
        replay_network,
        target_runtime,
        managed_by: "traffic-e2e",
    })
}

async fn run_managed_runtime(options: PreflightRecordingOptions) -> Result<ManagedRuntimeResult> {
    let (target_root, config) = resolve_project(&options.target_root)?;
    let run_id = options
        .run_id
        .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());
    let manifest = target_root
        .join(crate::repository::LOCAL_ROOT)
        .join("preflight")
        .join(&run_id)
        .join("artifacts/recordings")
        .join(&run_id)
        .join("recording-run.json");
    let recorder_config = &config.recorder_config;
    ensure!(
        recorder_config.is_file(),
        "recorder config does not exist: {}",
        recorder_config.display()
    );
    let source_traffic_policy = &config.source_traffic_policy;
    ensure!(
        source_traffic_policy.is_file(),
        "source traffic policy does not exist: {}",
        source_traffic_policy.display()
    );
    let recorder = crate::config::AppConfig::load_static(recorder_config)?;
    ensure!(
        recorder.recording.post_ready_quiet_period() >= std::time::Duration::from_secs(15),
        "managed recording requires a post-ready quiet period of at least 15 seconds"
    );
    ensure!(
        !recorder.http_gateway.enabled || recorder.http_gateway.ready.enabled,
        "managed HTTP recording requires an enabled http_gateway.ready probe"
    );
    if recorder.http_gateway.enabled {
        listen_preflight::require_available(recorder.http_gateway.listen).await?;
    }
    let (_, target_port) = http_origin_endpoint(&config.target_http_origin, "preflight target")?;
    ensure!(
        target_port == config.target_port,
        "preflight target origin port {target_port} does not match configured target port {}",
        config.target_port
    );
    let recording_origin = format!("http://127.0.0.1:{}", recorder.http_gateway.listen.port());
    let executable = crate::engine_binary::installed_executable()?;
    ensure_executable(&executable, "traffic-e2e binary")?;
    let encryption_key = encryption_key::load_or_create(&target_root)?;
    let assets = stage_assets(&target_root)?;
    crate::source_snapshot::write_runtime_projection(
        &assets.join("source-runtime.json"),
        &target_root,
    )?;
    startup::stage_assets(&assets, &target_root, &config)?;
    runtime_outputs::stage_assets(&assets, &config.target_runtime_outputs)?;
    let runtime_output_root = target_root
        .join(crate::repository::LOCAL_RUNTIME_OUTPUTS_ROOT)
        .join("preflight")
        .join(&run_id);
    ensure!(
        !runtime_output_root
            .to_string_lossy()
            .contains([',', '\r', '\n']),
        "target runtime output host path contains an unsupported delimiter"
    );
    let mut command = Command::new("bash");
    command
        .arg(assets.join("manage-platform.sh"))
        .arg("preflight")
        .current_dir(&target_root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .env(crate::request_headers::ENCRYPTION_KEY_ENV, encryption_key)
        .env("TRAFFIC_E2E_BIN", executable)
        .env("TRAFFIC_E2E_TARGET_ROOT", &target_root)
        .env(
            "TRAFFIC_E2E_SOURCE_RUNTIME",
            assets.join("source-runtime.json"),
        )
        .env(
            "TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE",
            assets.join("target-startup-mounts.tsv"),
        )
        .env(
            "TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE",
            assets.join("target-runtime-outputs.tsv"),
        )
        .env(
            "TRAFFIC_E2E_HTTP_RECORDING_ENABLED",
            recorder.http_gateway.enabled.to_string(),
        )
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
        .env("TRAFFIC_E2E_SOURCE_TRAFFIC_POLICY", source_traffic_policy)
        .env("TRAFFIC_E2E_PLATFORM_ASSETS", &assets)
        .arg("--duration-seconds")
        .arg(options.duration_seconds.to_string())
        .arg("--run-id")
        .arg(&run_id);
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
    let source_snapshot_id = crate::source_snapshot::load(&target_root)?
        .manifest
        .snapshot_id;
    Ok(ManagedRuntimeResult {
        run_id,
        target_root,
        source_snapshot_id,
        manifest,
    })
}

pub(crate) fn endpoint_port(endpoint: &str, label: &str) -> Result<u16> {
    let (_, port) = endpoint
        .rsplit_once(':')
        .with_context(|| format!("{label} must contain a port"))?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("{label} has an invalid port"))?;
    ensure!(port > 0, "{label} port must be greater than zero");
    Ok(port)
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

fn http_origin_endpoint(origin: &str, label: &str) -> Result<(String, u16)> {
    let origin = url::Url::parse(origin).with_context(|| format!("invalid {label} origin"))?;
    ensure!(
        matches!(origin.scheme(), "http" | "https"),
        "{label} origin must use HTTP or HTTPS"
    );
    let host = origin
        .host_str()
        .with_context(|| format!("{label} origin has no host"))?;
    let port = origin
        .port_or_known_default()
        .with_context(|| format!("{label} origin has no port"))?;
    Ok((host.to_string(), port))
}
