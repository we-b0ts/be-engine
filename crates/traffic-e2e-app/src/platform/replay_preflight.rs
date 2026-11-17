use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use tokio::process::{Child, Command};

use crate::e2e_run::ResolvedProjectConfig;
use crate::replay::{ReplayControlConfig, run_replay_control};

const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const REPLAY_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const REPLAY_CA_CONTAINER_PATH: &str = "/traffic-e2e/trust/replay-ca.pem";

#[derive(Debug, Clone, Serialize)]
pub struct ManagedReplayNetworkPreflightResult {
    pub status: &'static str,
    pub probe_image: &'static str,
    pub process_user: &'static str,
    pub positive: ReplayPositiveProbeResult,
    pub negative: ReplayNegativeProbeResult,
    pub direct_egress: ReplayDirectEgressProbeResult,
    pub cleanup: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedTargetRuntimePreflightResult {
    pub status: &'static str,
    pub image_id: String,
    pub container_name: String,
    pub process_user: &'static str,
    pub readiness_path: String,
    pub readiness_status: u16,
    pub checks: ManagedTargetRuntimePreflightChecks,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedTargetRuntimePreflightChecks {
    pub process_identity: bool,
    pub startup_environment: bool,
    pub runtime_mounts: bool,
    pub listen_all_interfaces: bool,
    pub readiness: bool,
    pub graceful_shutdown: bool,
    pub cleanup: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayPositiveProbeResult {
    pub authority: &'static str,
    pub http_status: u16,
    pub fake_ip: Ipv4Addr,
    pub global_http_exchanges_consumed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayNegativeProbeResult {
    pub authority: &'static str,
    pub absent_from_replay_targets: bool,
    pub connection_rejected: bool,
    pub evidence_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayDirectEgressProbeResult {
    pub destination: &'static str,
    pub blocked: bool,
}

pub(super) async fn run(
    target_root: &Path,
    project: &ResolvedProjectConfig,
    run_id: &str,
    manifest: &Path,
    target_image: &crate::TargetImage,
) -> Result<(
    ManagedReplayNetworkPreflightResult,
    ManagedTargetRuntimePreflightResult,
)> {
    let runtime_dir = target_root
        .join(crate::repository::LOCAL_ROOT)
        .join("preflight")
        .join(run_id)
        .join("replay-network");
    let result = run_in_runtime_dir(
        target_root,
        project,
        run_id,
        manifest,
        target_image,
        &runtime_dir,
    )
    .await;
    let ownership = restore_artifact_ownership(&runtime_dir).await;
    combine_artifact_ownership(result, ownership)
}

async fn run_in_runtime_dir(
    target_root: &Path,
    project: &ResolvedProjectConfig,
    run_id: &str,
    manifest: &Path,
    target_image: &crate::TargetImage,
    runtime_dir: &Path,
) -> Result<(
    ManagedReplayNetworkPreflightResult,
    ManagedTargetRuntimePreflightResult,
)> {
    let run_dir = manifest
        .parent()
        .context("preflight recording manifest has no run directory")?;
    tokio::fs::create_dir_all(runtime_dir)
        .await
        .with_context(|| {
            format!(
                "failed to create Replay network preflight directory {}",
                runtime_dir.display()
            )
        })?;
    tokio::fs::set_permissions(runtime_dir, std::fs::Permissions::from_mode(0o700)).await?;

    let session = runtime_dir.join("session.json");
    let report = runtime_dir.join("replay-report.json");
    let control_socket = crate::replay::allocate_control_socket();
    let mut child = spawn_replay(
        target_root,
        project,
        run_dir,
        runtime_dir,
        &session,
        &report,
        &control_socket,
    )?;
    let anchor =
        crate::target_container::runtime_name(target_root, "preflight-replay", run_id, "anchor")?;
    let target =
        crate::target_container::runtime_name(target_root, "preflight-replay", run_id, "target")?;
    let result = async {
        let ca_cert = wait_replay_ready(project, &session)
            .await
            .context("replay_network preflight failed")?;
        let network = run_checks(&session, &anchor, run_id, &ca_cert)
            .await
            .context("replay_network preflight failed")?;
        let target_runtime = run_target_runtime(
            target_root,
            project,
            run_id,
            runtime_dir,
            &anchor,
            &target,
            &ca_cert,
            target_image,
        )
        .await
        .context("target_runtime preflight failed")?;
        Ok::<_, anyhow::Error>((network, target_runtime))
    }
    .await;
    let cleanup = cleanup(
        target_root,
        &session,
        &control_socket,
        &target,
        &anchor,
        &mut child,
    )
    .await;
    match (result, cleanup) {
        (Ok((mut network, mut target_runtime)), Ok(())) => {
            network.cleanup = true;
            target_runtime.checks.cleanup = true;
            Ok((network, target_runtime))
        }
        (Ok(_), Err(error)) => Err(error).context("target_runtime preflight cleanup failed"),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "initialization preflight cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

async fn restore_artifact_ownership(runtime_dir: &Path) -> Result<()> {
    match tokio::fs::symlink_metadata(runtime_dir).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect Replay preflight artifact directory {}",
                    runtime_dir.display()
                )
            });
        }
    }
    let owner = crate::ArtifactOwner::invoking()?;
    owner
        .assign_to(runtime_dir)
        .await
        .context("failed to restore Replay preflight artifacts to the invoking user")
}

fn combine_artifact_ownership<T>(result: Result<T>, ownership: Result<()>) -> Result<T> {
    match (result, ownership) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(ownership_error)) => Err(error.context(format!(
            "Replay preflight artifact ownership also failed: {ownership_error:#}"
        ))),
    }
}

async fn wait_replay_ready(project: &ResolvedProjectConfig, session: &Path) -> Result<PathBuf> {
    let ready = control(session, "wait_ready", Some(project.replay_startup_timeout))
        .await
        .context("Replay network preflight did not become ready")?;
    let ca_cert = ready
        .pointer("/session/ca_cert_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .context("Replay network preflight readiness has no CA certificate")?;
    require_regular_file(&ca_cert, "Replay CA certificate")?;
    Ok(ca_cert)
}

#[allow(clippy::too_many_arguments)]
async fn run_target_runtime(
    target_root: &Path,
    project: &ResolvedProjectConfig,
    run_id: &str,
    runtime_dir: &Path,
    anchor: &str,
    container: &str,
    ca_cert: &Path,
    image: &crate::TargetImage,
) -> Result<ManagedTargetRuntimePreflightResult> {
    let target = crate::target_container::TargetContainerConfig::from_project(
        target_root.to_path_buf(),
        project,
    );
    crate::target_container::start_target(crate::target_container::TargetStartOptions {
        config: &target,
        image,
        container_name: container.to_string(),
        network_container: anchor.to_string(),
        operation: "preflight-replay",
        run_id: run_id.to_string(),
        replay_ca_cert: Some(ca_cert.to_path_buf()),
        runtime_outputs: &project.target_runtime_outputs,
        runtime_output_root: runtime_dir.join("target-runtime-outputs"),
    })
    .await?;

    crate::e2e_run::wait_until_ready(project)
        .await
        .context("target did not satisfy the configured readiness contract")?;
    crate::target_container::verify_target_identity(container).await?;
    crate::target_container::verify_startup_environment(container, target_root).await?;
    let snapshot = crate::startup::load_startup_snapshot(target_root, &target.startup)?;
    crate::target_container::verify_runtime_mounts(
        container,
        snapshot.mounts(),
        &project.target_runtime_outputs,
        true,
    )
    .await?;
    crate::target_container::verify_listen_address(container, target.port).await?;
    crate::target_container::capture_diagnostics(container, runtime_dir).await?;
    let stop = crate::target_container::stop_target(target_root, container).await?;
    ensure!(
        stop.exit_code == 0 && stop.removed,
        "target did not stop cleanly after SIGTERM: exit code {}",
        stop.exit_code
    );

    Ok(ManagedTargetRuntimePreflightResult {
        status: "passed",
        image_id: image.id.clone(),
        container_name: container.to_string(),
        process_user: crate::TRAFFIC_PROCESS_USER,
        readiness_path: project.target_readiness_path.clone(),
        readiness_status: project.target_readiness_status,
        checks: ManagedTargetRuntimePreflightChecks {
            process_identity: true,
            startup_environment: true,
            runtime_mounts: true,
            listen_all_interfaces: true,
            readiness: true,
            graceful_shutdown: true,
            cleanup: false,
        },
    })
}

fn spawn_replay(
    target_root: &Path,
    project: &ResolvedProjectConfig,
    run_dir: &Path,
    runtime_dir: &Path,
    session: &Path,
    report: &Path,
    control_socket: &Path,
) -> Result<Child> {
    let executable = crate::engine_binary::executable()?;
    let stdout = File::create(runtime_dir.join("replay.stdout.log"))?;
    let stderr = File::create(runtime_dir.join("replay.stderr.log"))?;
    let mut command = Command::new(&executable);
    command
        .arg("replay")
        .arg("--report")
        .arg(report)
        .arg("--session")
        .arg(session)
        .arg("--control-socket")
        .arg(control_socket)
        .arg("--policy")
        .arg(&project.replay_policy)
        .arg("--recorder-config")
        .arg(&project.recorder_config)
        .arg(run_dir)
        .current_dir(target_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }
    command.spawn().with_context(|| {
        format!(
            "failed to start Replay preflight with {}",
            executable.display()
        )
    })
}

async fn run_checks(
    session: &Path,
    anchor: &str,
    run_id: &str,
    ca_cert: &Path,
) -> Result<ManagedReplayNetworkPreflightResult> {
    let before = report(session).await?;
    let fake_ip = replay_target_ip(&before, crate::network_probe::POSITIVE_AUTHORITY, 443)?;
    ensure!(
        !has_replay_target(&before, crate::network_probe::NEGATIVE_AUTHORITY),
        "{} must not be present in Replay targets",
        crate::network_probe::NEGATIVE_AUTHORITY
    );
    ensure!(
        report_count(&before, "matched_http_exchange_count")? == 0,
        "Replay network preflight started with matched HTTP exchanges"
    );

    crate::target_container::create_anchor(anchor, true, "preflight-replay", run_id).await?;
    let positive = run_probe(
        anchor,
        Some(ca_cert),
        &[
            "--silent",
            "--show-error",
            "--connect-timeout",
            "10",
            "--max-time",
            "15",
            "--cacert",
            REPLAY_CA_CONTAINER_PATH,
            "--user-agent",
            crate::network_probe::SYSTEM_USER_AGENT,
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code} %{remote_ip}",
            crate::network_probe::POSITIVE_URL,
        ],
    )
    .await?;
    ensure!(
        positive.status.success(),
        "Replay positive probe failed: {}",
        String::from_utf8_lossy(&positive.stderr).trim()
    );
    let (http_status, remote_ip) = parse_positive_output(&positive.stdout)?;
    ensure!(
        remote_ip == fake_ip,
        "Replay positive probe connected to {remote_ip}, expected assigned fake IP {fake_ip}"
    );

    let after_positive = report(session).await?;
    ensure_global_match(&after_positive, fake_ip)?;
    let matched_after_positive = report_count(&after_positive, "matched_http_exchange_count")?;

    let negative = run_probe(
        anchor,
        Some(ca_cert),
        &[
            "--silent",
            "--show-error",
            "--connect-timeout",
            "5",
            "--max-time",
            "8",
            "--cacert",
            REPLAY_CA_CONTAINER_PATH,
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            crate::network_probe::NEGATIVE_URL,
        ],
    )
    .await?;
    ensure!(
        !negative.status.success(),
        "Replay negative probe unexpectedly reached {}",
        crate::network_probe::NEGATIVE_AUTHORITY
    );

    let after_negative = report(session).await?;
    ensure_unrecorded_endpoint_evidence(
        &after_negative,
        crate::network_probe::NEGATIVE_AUTHORITY,
        443,
    )?;
    ensure!(
        report_count(&after_negative, "matched_http_exchange_count")? == matched_after_positive,
        "Replay negative probe unexpectedly matched a recorded HTTP exchange"
    );
    ensure!(
        after_negative
            .get("unmatched_http_requests")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "Replay negative probe reached the HTTP replay matcher"
    );

    let direct = run_probe(
        anchor,
        None,
        &[
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "http://1.1.1.1/",
        ],
    )
    .await?;
    ensure!(
        direct.status.code() == Some(7),
        "Replay direct external egress probe must be rejected (curl exit 7), got {}: {}",
        direct.status,
        String::from_utf8_lossy(&direct.stderr).trim()
    );

    Ok(ManagedReplayNetworkPreflightResult {
        status: "passed",
        probe_image: crate::network_probe::IMAGE,
        process_user: crate::TRAFFIC_PROCESS_USER,
        positive: ReplayPositiveProbeResult {
            authority: crate::network_probe::POSITIVE_AUTHORITY,
            http_status,
            fake_ip,
            global_http_exchanges_consumed: 1,
        },
        negative: ReplayNegativeProbeResult {
            authority: crate::network_probe::NEGATIVE_AUTHORITY,
            absent_from_replay_targets: true,
            connection_rejected: true,
            evidence_verified: true,
        },
        direct_egress: ReplayDirectEgressProbeResult {
            destination: "1.1.1.1:80",
            blocked: true,
        },
        cleanup: false,
    })
}

async fn run_probe(
    anchor: &str,
    ca_cert: Option<&Path>,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut command = Command::new("docker");
    command
        .args(["run", "--rm", "--platform", "linux/amd64"])
        .args(["--network", &format!("container:{anchor}")])
        .args(["--user", crate::TRAFFIC_PROCESS_USER])
        .args(["--cap-drop", "ALL"])
        .args(["--security-opt", "no-new-privileges"]);
    if let Some(ca_cert) = ca_cert {
        command.args([
            "--mount",
            &format!(
                "type=bind,source={},target={REPLAY_CA_CONTAINER_PATH},readonly",
                ca_cert.display()
            ),
        ]);
    }
    command.arg(crate::network_probe::IMAGE).args(args);
    tokio::time::timeout(PROBE_TIMEOUT, command.output())
        .await
        .context("network probe container timed out")?
        .context("failed to run network probe container")
}

fn parse_positive_output(output: &[u8]) -> Result<(u16, Ipv4Addr)> {
    let output = std::str::from_utf8(output).context("positive probe returned non-UTF-8 output")?;
    let mut fields = output.split_whitespace();
    let status = fields
        .next()
        .context("positive probe returned no HTTP status")?
        .parse::<u16>()
        .context("positive probe returned an invalid HTTP status")?;
    let remote_ip = fields
        .next()
        .context("positive probe returned no remote IP")?
        .parse::<Ipv4Addr>()
        .context("positive probe returned an invalid remote IP")?;
    ensure!(
        fields.next().is_none() && (100..=599).contains(&status),
        "positive probe returned invalid output {output:?}"
    );
    Ok((status, remote_ip))
}

fn replay_target_ip(report: &Value, host: &str, port: u16) -> Result<Ipv4Addr> {
    report
        .get("targets")
        .and_then(Value::as_array)
        .context("Replay report has no targets")?
        .iter()
        .find(|target| {
            target.get("host").and_then(Value::as_str) == Some(host)
                && target.get("port").and_then(Value::as_u64) == Some(u64::from(port))
                && target.get("protocol").and_then(Value::as_str) == Some("https")
        })
        .and_then(|target| target.get("fake_ip"))
        .and_then(Value::as_str)
        .context("Replay targets do not contain the demo.test HTTPS Global dependency")?
        .parse()
        .context("Replay assigned an invalid fake IP to demo.test")
}

fn has_replay_target(report: &Value, host: &str) -> bool {
    report
        .get("targets")
        .and_then(Value::as_array)
        .is_some_and(|targets| {
            targets
                .iter()
                .any(|target| target.get("host").and_then(Value::as_str) == Some(host))
        })
}

fn ensure_unrecorded_endpoint_evidence(report: &Value, host: &str, port: u16) -> Result<()> {
    let events = report
        .get("unrecorded_targets")
        .and_then(Value::as_array)
        .context("Replay report has no unrecorded_targets")?;
    let matching = events
        .iter()
        .filter(|event| {
            event.pointer("/target/host").and_then(Value::as_str) == Some(host)
                && event.pointer("/target/port").and_then(Value::as_u64) == Some(u64::from(port))
                && event.get("reason").and_then(Value::as_str)
                    == Some(crate::replay::UNRECORDED_ENDPOINT_REASON)
        })
        .count();
    ensure!(
        matching == 1,
        "Replay negative probe expected exactly one rejected endpoint evidence for {host}:{port}, found {matching}"
    );
    Ok(())
}

fn ensure_global_match(report: &Value, fake_ip: Ipv4Addr) -> Result<()> {
    ensure!(
        report_count(report, "matched_http_exchange_count")? == 1,
        "Replay positive probe must consume exactly one HTTP exchange"
    );
    let matches = report
        .get("matched_http_exchanges")
        .and_then(Value::as_array)
        .context("Replay report has no matched_http_exchanges")?;
    ensure!(
        matches.len() == 1,
        "Replay positive probe has ambiguous matches"
    );
    let matched = &matches[0];
    ensure!(
        matched.get("source").and_then(Value::as_str) == Some("startup")
            && matched.pointer("/target/host").and_then(Value::as_str)
                == Some(crate::network_probe::POSITIVE_AUTHORITY)
            && matched.pointer("/target/port").and_then(Value::as_u64) == Some(443)
            && matched.get("method").and_then(Value::as_str) == Some("GET")
            && matched.get("status").and_then(Value::as_u64).is_some(),
        "Replay positive probe did not consume the expected demo.test Global HTTP exchange"
    );
    ensure!(
        report
            .get("targets")
            .and_then(Value::as_array)
            .is_some_and(|targets| targets.iter().any(|target| {
                target.get("fake_ip").and_then(Value::as_str) == Some(&fake_ip.to_string())
            })),
        "Replay positive probe fake IP is not present in Replay targets"
    );
    Ok(())
}

fn report_count(report: &Value, field: &str) -> Result<u64> {
    report
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("Replay report has no numeric {field}"))
}

async fn report(session: &Path) -> Result<Value> {
    let response = control(session, "report", None).await?;
    response
        .get("report")
        .cloned()
        .context("Replay control report response has no report")
}

async fn control(session: &Path, command: &str, timeout: Option<Duration>) -> Result<Value> {
    run_replay_control(ReplayControlConfig {
        session_path: session.to_path_buf(),
        command: command.to_string(),
        case_id: None,
        fail_on_dirty: false,
        fail_on_incomplete: false,
        wait_timeout: timeout,
    })
    .await
}

async fn cleanup(
    target_root: &Path,
    session: &Path,
    control_socket: &Path,
    target: &str,
    anchor: &str,
    child: &mut Child,
) -> Result<()> {
    let process_cleanup: Result<()> = async {
        if child.try_wait()?.is_none() && session.is_file() {
            let _ = control(session, "stop", None).await;
        }
        match tokio::time::timeout(REPLAY_STOP_TIMEOUT, child.wait()).await {
            Ok(status) => {
                status.context("failed to wait for Replay preflight shutdown")?;
                Ok(())
            }
            Err(_) => {
                #[cfg(unix)]
                super::signal_process_group(child, libc::SIGTERM);
                #[cfg(not(unix))]
                child
                    .start_kill()
                    .context("failed to terminate Replay preflight")?;
                match tokio::time::timeout(REPLAY_STOP_TIMEOUT, child.wait()).await {
                    Ok(status) => {
                        status.context("failed to wait for Replay preflight after SIGTERM")?;
                        Ok(())
                    }
                    Err(_) => {
                        #[cfg(unix)]
                        super::signal_process_group(child, libc::SIGKILL);
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        anyhow::bail!(
                            "Replay preflight ignored graceful stop and SIGTERM; interception cleanup cannot be guaranteed"
                        )
                    }
                }
            }
        }
    }
    .await;
    let anchor_cleanup =
        crate::target_container::force_remove_runtime(target_root, &[target, anchor]).await;
    let socket_cleanup = match tokio::fs::remove_file(control_socket).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove Replay control socket {}",
                control_socket.display()
            )
        }),
    };
    let runtime_cleanup = match (process_cleanup, anchor_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(anchor_error)) => {
            Err(error.context(format!("anchor cleanup also failed: {anchor_error:#}")))
        }
    };
    runtime_cleanup?;
    socket_cleanup
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} is not a regular file: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_positive_probe_output() {
        assert_eq!(
            parse_positive_output(b"302 198.19.0.3").unwrap(),
            (302, "198.19.0.3".parse().unwrap())
        );
        assert!(parse_positive_output(b"000").is_err());
        assert!(parse_positive_output(b"200 10.0.0.1 trailing").is_err());
    }

    #[test]
    fn preserves_preflight_and_ownership_errors() {
        let error = combine_artifact_ownership::<()>(
            Err(anyhow::anyhow!("preflight error")),
            Err(anyhow::anyhow!("ownership error")),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("preflight error"));
        assert!(message.contains("ownership error"));
    }

    #[test]
    fn target_runtime_result_reports_the_readiness_smoke_contract() {
        let result = ManagedTargetRuntimePreflightResult {
            status: "passed",
            image_id: format!("sha256:{}", "a".repeat(64)),
            container_name: "traffic-e2e-example-preflight-target".to_string(),
            process_user: "998:998",
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            checks: ManagedTargetRuntimePreflightChecks {
                process_identity: true,
                startup_environment: true,
                runtime_mounts: true,
                listen_all_interfaces: true,
                readiness: true,
                graceful_shutdown: true,
                cleanup: true,
            },
        };

        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["readiness_path"], "/healthz");
        assert_eq!(value["readiness_status"], 404);
        assert_eq!(value["checks"]["graceful_shutdown"], true);
        assert_eq!(value["checks"]["cleanup"], true);
    }

    #[test]
    fn identifies_positive_and_negative_replay_targets() {
        let report = serde_json::json!({
            "targets": [
                {"host": "demo.test", "port": 443, "fake_ip": "198.19.0.3", "protocol": "https"}
            ]
        });
        assert_eq!(
            replay_target_ip(&report, "demo.test", 443).unwrap(),
            "198.19.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert!(!has_replay_target(&report, "example.com"));
    }

    #[test]
    fn validates_unrecorded_endpoint_evidence() {
        let report = serde_json::json!({
            "unrecorded_targets": [{
                "case_id": "case-a",
                "target": {"host": "example.com", "port": 443},
                "reason": crate::replay::UNRECORDED_ENDPOINT_REASON,
            }]
        });

        ensure_unrecorded_endpoint_evidence(&report, "example.com", 443).unwrap();
        assert!(ensure_unrecorded_endpoint_evidence(&report, "example.com", 80).is_err());
    }
}
