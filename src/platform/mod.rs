use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde::Serialize;
use tokio::process::Command;

use crate::e2e_run::resolve_project;
use crate::recording_api::RecordingApi;

#[cfg(test)]
mod asset_contract_tests;
mod assets;
mod listen_preflight;
#[cfg(test)]
mod manager_tests;
#[cfg(test)]
mod mount_tests;
mod preflight;
mod recording_input;
mod recovery;
mod replay_preflight;
mod startup;

use assets::{stage_assets, write_asset};

pub use preflight::{
    ManagedMotanPreflightResult, ManagedMotanRecordingResult, ManagedRecordingPreflightOptions,
    ManagedRecordingPreflightRecordingResult, ManagedRecordingPreflightResult,
    ManagedTargetImagePreflightChecks, ManagedTargetImagePreflightResult, MotanPreflightStatus,
};
pub use recording_input::{
    ManagedRecordingInputCompletion, ManagedRecordingInputOptions, ManagedRecordingInputResult,
    drive_managed_recording_input,
};
pub use recovery::{ManagedRecordingRecoveryResult, recover_managed_recording};
pub use replay_preflight::{
    ManagedReplayNetworkPreflightResult, ReplayDirectEgressProbeResult, ReplayNegativeProbeResult,
    ReplayPositiveProbeResult,
};
const MANAGER: &str = include_str!("assets/manage-platform.sh");
const COMPARISON_TARGET_NETWORK: &str = include_str!("assets/comparison-target-network.sh");
const RECORDER_RUNTIME: &str = include_str!("assets/recorder-runtime.sh");
const PLATFORM_MOUNTS: &str = include_str!("assets/platform-mounts.sh");
const PREFLIGHT_BUSINESS_INPUT: &str = include_str!("assets/preflight-business-input.sh");
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

    fn requires_listener_preflight(self) -> bool {
        self != Self::Recording(ManagedRecordingOperation::RecordComparison)
    }
}

#[derive(Debug, Clone)]
pub struct ManagedRecordingOptions {
    pub target_root: PathBuf,
    pub operation: ManagedRecordingOperation,
    pub run_id: Option<String>,
    pub duration_seconds: NonZeroU64,
    pub baseline_recheck: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub motan: Option<ManagedMotanRecordingResult>,
    pub managed_by: &'static str,
}

struct ManagedRuntimeResult {
    run_id: String,
    target_root: PathBuf,
    source_container: String,
    breeze_container: Option<String>,
    manifest: PathBuf,
    motan: Option<MotanRuntimeContext>,
}

#[derive(Debug, Clone)]
struct MotanRuntimeContext {
    source_port: u16,
    gateway_port: u16,
    motan_replay_command: String,
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
    let motan = result
        .motan
        .as_ref()
        .map(|_| preflight::validate_motan_recording(&result.manifest))
        .transpose()?;
    Ok(ManagedRecordingResult {
        operation,
        run_id: result.run_id,
        target_root: result.target_root,
        source_container: result.source_container,
        breeze_container: result.breeze_container,
        manifest: result.manifest,
        motan,
        managed_by: "traffic-e2e",
    })
}

pub async fn run_managed_recording_preflight(
    options: ManagedRecordingPreflightOptions,
) -> Result<ManagedRecordingPreflightResult> {
    let (target_root, project) = resolve_project(&options.target_root)?;
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
    let runtime = run_managed_runtime(
        ManagedRecordingOptions {
            target_root,
            operation: ManagedRecordingOperation::Record,
            run_id: None,
            duration_seconds: options.duration_seconds,
            baseline_recheck: false,
            apis: options.apis,
            per_api_case_limit: options.per_api_case_limit,
            request_source: None,
        },
        ManagedRuntimeOperation::Preflight,
    )
    .await?;
    let breeze_enabled = runtime.breeze_container.is_some();
    let evidence = preflight::validate(&runtime.manifest, runtime.motan.is_some(), breeze_enabled)?;
    let replay_network = replay_preflight::run(
        &runtime.target_root,
        &project,
        &runtime.run_id,
        &runtime.manifest,
    )
    .await
    .context("replay_network preflight failed")?;
    let motan = runtime.motan.as_ref().map(|motan| {
        let status = evidence
            .motan_status
            .expect("enabled Motan preflight must have a status");
        preflight::ManagedMotanPreflightResult {
            status,
            observed_cases: evidence.motan_cases,
            source_port: motan.source_port,
            gateway_port: motan.gateway_port,
            validation_deferred: status == preflight::MotanPreflightStatus::NotObserved,
            motan_replay_command: motan.motan_replay_command.clone(),
            required_action: (status == preflight::MotanPreflightStatus::NotObserved).then_some(
                "No Motan request was observed. Ask whether to rerun preflight with controlled \
                 traffic now or defer Motan validation to the first managed recording.",
            ),
        }
    });
    let validation_deferred = motan
        .as_ref()
        .is_some_and(|motan| motan.validation_deferred);
    Ok(ManagedRecordingPreflightResult {
        status: if validation_deferred {
            "passed_with_deferred_validation"
        } else {
            "passed"
        },
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
            status: if validation_deferred {
                "passed_with_deferred_validation"
            } else {
                "passed"
            },
            run_id: runtime.run_id,
            target_root: runtime.target_root,
            source_container: runtime.source_container,
            probe_kind: evidence.probe_kind,
            breeze_container: runtime.breeze_container,
            manifest: runtime.manifest,
            published_cases: evidence.published_cases,
            https_interception_verified: evidence.https_interception_verified,
            global_probe_dependency_verified: evidence.global_probe_dependency_verified,
            breeze_dns_resolution_verified: breeze_enabled
                .then_some(evidence.breeze_dns_resolution_verified),
            motan,
        },
        replay_network,
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
    let recorder_config = &config.recorder_config;
    ensure!(
        recorder_config.is_file(),
        "recorder config does not exist: {}",
        recorder_config.display()
    );
    let coordinator_rules = &config.coordinator_rules;
    ensure!(
        coordinator_rules.is_file(),
        "coordinator rules do not exist: {}",
        coordinator_rules.display()
    );
    let managed_candidate = crate::config::managed_comparison_candidate(config.target_port);
    let recorder = crate::config::AppConfig::load_comparison_recording_with_candidate(
        recorder_config,
        Some(&managed_candidate),
    )?;
    let motan = if recorder.motan_gateway.enabled
        && runtime_operation
            != ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
    {
        ensure!(
            recorder.recording.traffic_jsonl != crate::config::TrafficJsonlMode::Off,
            "managed Motan recording requires recording.traffic_jsonl to be errors or full so \
             gateway failures remain verifiable"
        );
        let source_port = endpoint_port(
            &recorder.motan_gateway.matched_upstream,
            "motan_gateway.matched_upstream",
        )?;
        let gateway_port = recorder.motan_gateway.listen.port();
        Some(MotanRuntimeContext {
            source_port,
            gateway_port,
            motan_replay_command: format!(
                "motan-replay --input-raw :{source_port} --output-rpc 127.0.0.1:{gateway_port}"
            ),
        })
    } else {
        None
    };
    let comparison_motan_port = if recorder.motan_gateway.enabled
        && runtime_operation
            == ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
    {
        Some(endpoint_port(
            &recorder.motan_gateway.matched_upstream,
            "motan_gateway.matched_upstream",
        )?)
    } else {
        None
    };
    ensure!(
        recorder.recording.post_ready_quiet_period() >= std::time::Duration::from_secs(15),
        "managed recording requires a post-ready quiet period of at least 15 seconds"
    );
    ensure!(
        !recorder.http_gateway.enabled || recorder.http_gateway.ready.enabled,
        "managed HTTP recording requires an enabled http_gateway.ready probe"
    );
    if runtime_operation.requires_listener_preflight() && recorder.http_gateway.enabled {
        listen_preflight::require_available(recorder.http_gateway.listen).await?;
    }
    let target_image = if runtime_operation
        == ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
    {
        crate::startup::load_startup_snapshot(&target_root, &config.target_startup)?;
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
    let comparison = recorder
        .comparison_recording
        .as_ref()
        .context("managed recording requires comparison configuration")?;
    let (source_origin, source_host, source_port) = if recorder.http_gateway.enabled {
        let source_origin = comparison
            .baseline_upstream(&recorder.http_gateway)
            .to_string();
        let (source_host, source_port) = http_origin_endpoint(&source_origin, "comparison source")?;
        (source_origin, source_host, source_port)
    } else {
        // These values remain present for the shared platform script contract,
        // but are not contacted when HTTP recording is disabled.
        ("http://127.0.0.1:1".to_string(), "127.0.0.1".to_string(), 1)
    };
    let (_, target_port) = http_origin_endpoint(&config.target_http_origin, "comparison target")?;
    ensure!(
        target_port == config.target_port,
        "comparison target origin port {target_port} does not match configured target port {}",
        config.target_port
    );
    let recording_origin = format!("http://127.0.0.1:{}", recorder.http_gateway.listen.port());
    let motan_recording_upstream = if recorder.motan_gateway.enabled {
        format!("127.0.0.1:{}", recorder.motan_gateway.listen.port())
    } else {
        String::new()
    };
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
    let finite_input_comparison = runtime_operation
        == ManagedRuntimeOperation::Recording(ManagedRecordingOperation::RecordComparison)
        && request_source.is_some();
    let managed_comparison_listen = listen_preflight::managed_finite_comparison(
        finite_input_comparison && recorder.http_gateway.enabled,
        recorder.http_gateway.listen,
    );
    let managed_comparison_motan_listen = listen_preflight::managed_finite_comparison(
        finite_input_comparison && recorder.motan_gateway.enabled,
        recorder.motan_gateway.listen,
    );
    let executable = crate::engine_binary::executable()?;
    ensure_executable(&executable, "traffic-e2e binary")?;
    let assets = stage_assets(&target_root)?;
    startup::stage_assets(&assets, &target_root, &config)?;
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
        .env(
            "TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE",
            assets.join("target-startup-mounts.tsv"),
        )
        .env(
            "TRAFFIC_E2E_TARGET_STARTUP_ENV_FILE",
            assets.join("target-startup.env"),
        )
        .env("TRAFFIC_E2E_TARGET_PORT", config.target_port.to_string())
        .env(
            "TRAFFIC_E2E_COMPARISON_MOTAN_ENABLED",
            comparison_motan_port.is_some().to_string(),
        )
        .env(
            "TRAFFIC_E2E_HTTP_RECORDING_ENABLED",
            recorder.http_gateway.enabled.to_string(),
        )
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
        .env("TRAFFIC_E2E_SOURCE_HOST", source_host)
        .env("TRAFFIC_E2E_SOURCE_PORT", source_port.to_string())
        .env("TRAFFIC_E2E_RECORDING_ORIGIN", recording_origin)
        .env(
            "TRAFFIC_E2E_MOTAN_RECORDING_UPSTREAM",
            motan_recording_upstream,
        )
        .env(
            "TRAFFIC_E2E_PREFLIGHT_MOTAN_ENABLED",
            (runtime_operation == ManagedRuntimeOperation::Preflight && motan.is_some())
                .to_string(),
        )
        .env(
            "TRAFFIC_E2E_SOURCE_READY_PATH",
            &recorder.http_gateway.ready.path,
        )
        .env(
            "TRAFFIC_E2E_SOURCE_READY_STATUS",
            recorder.http_gateway.ready.success_status.to_string(),
        )
        .env("TRAFFIC_E2E_RECORDER_CONFIG", recorder_config)
        .env("TRAFFIC_E2E_COORDINATOR_RULES", coordinator_rules)
        .env("TRAFFIC_E2E_REPLAY_POLICY", &config.replay_policy)
        .env("TRAFFIC_E2E_PLATFORM_ASSETS", &assets)
        .arg("--duration-seconds")
        .arg(options.duration_seconds.to_string())
        .arg("--run-id")
        .arg(&run_id);
    if let Some(listen) = managed_comparison_listen {
        command.env("TRAFFIC_E2E_MANAGED_COMPARISON_LISTEN", listen.to_string());
    }
    if let Some(listen) = managed_comparison_motan_listen {
        command.env(
            "TRAFFIC_E2E_MANAGED_COMPARISON_MOTAN_LISTEN",
            listen.to_string(),
        );
    }
    if let Some(port) = comparison_motan_port {
        command.env("TRAFFIC_E2E_TARGET_MOTAN_PORT", port.to_string());
    }
    if runtime_operation == ManagedRuntimeOperation::Preflight
        && let Some(motan) = &motan
    {
        command
            .env(
                "TRAFFIC_E2E_MOTAN_SOURCE_PORT",
                motan.source_port.to_string(),
            )
            .env(
                "TRAFFIC_E2E_MOTAN_GATEWAY_PORT",
                motan.gateway_port.to_string(),
            )
            .env(
                "TRAFFIC_E2E_MOTAN_REPLAY_COMMAND",
                &motan.motan_replay_command,
            );
    }
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
        motan,
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
