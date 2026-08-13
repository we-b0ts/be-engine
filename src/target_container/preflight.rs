use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tokio::process::Command;
use uuid::Uuid;

use super::model::{
    TargetContainerChecks, TargetContainerConfig, TargetContainerPreflightResult,
    TargetStartOptions,
};
use super::{
    bounded_logs, build_image, create_anchor, force_remove_runtime, is_running, runtime_name,
    start_target, stop_target, verify_listen_address, verify_startup_environment,
    verify_startup_mounts, verify_target_identity,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) async fn run_preflight(
    config: TargetContainerConfig,
) -> Result<TargetContainerPreflightResult> {
    let image = build_image(&config).await?;
    let run_id = Uuid::new_v4().simple().to_string();
    let anchor = runtime_name(&config.target_root, "preflight", &run_id, "anchor")?;
    let target = runtime_name(&config.target_root, "preflight", &run_id, "target")?;

    let result = run_preflight_runtime(&config, &image, &run_id, &anchor, &target).await;
    if let Err(cleanup_error) = force_remove_runtime(&config.target_root, &[&target, &anchor]).await
    {
        return match result {
            Ok(_) => Err(cleanup_error).context("target preflight cleanup failed"),
            Err(error) => Err(error.context(format!(
                "target preflight cleanup also failed: {cleanup_error:#}"
            ))),
        };
    }
    result.map(|checks| TargetContainerPreflightResult {
        status: "passed",
        image,
        checks,
    })
}

async fn run_preflight_runtime(
    config: &TargetContainerConfig,
    image: &super::TargetImage,
    run_id: &str,
    anchor: &str,
    target: &str,
) -> Result<TargetContainerChecks> {
    create_anchor(anchor, false, "preflight", run_id).await?;
    start_target(TargetStartOptions {
        config,
        image,
        container_name: target.to_string(),
        network_container: anchor.to_string(),
        operation: "preflight",
        run_id: run_id.to_string(),
        replay_ca_cert: None,
    })
    .await?;
    verify_target_identity(target).await?;
    verify_startup_environment(target, &config.startup, false, config.breeze_enabled).await?;
    let snapshot = crate::startup::load_startup_snapshot(&config.target_root, &config.startup)?;
    verify_startup_mounts(target, snapshot.mounts()).await?;
    wait_until_ready(config, anchor, target).await?;
    verify_listen_address(target, config.port).await?;
    let logs = bounded_logs(target).await?;
    ensure!(
        !logs.trim().is_empty(),
        "target emitted no stdout or stderr during preflight"
    );
    let stop = stop_target(&config.target_root, target).await?;
    ensure!(
        stop.exit_code == 0,
        "target exited with {} after SIGTERM",
        stop.exit_code
    );

    Ok(TargetContainerChecks {
        image_contract: true,
        process_identity: true,
        startup_snapshot: true,
        startup_environment: true,
        startup_mount_access: true,
        listen_all_interfaces: true,
        readiness: true,
        stdout_stderr_logging: true,
        graceful_shutdown: true,
        cleanup: true,
    })
}

async fn wait_until_ready(
    config: &TargetContainerConfig,
    anchor: &str,
    target: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + config.startup_timeout;
    let url = format!("http://127.0.0.1:{}{}", config.port, config.readiness_path);
    loop {
        if !is_running(target).await? {
            anyhow::bail!("target exited before its readiness endpoint became available");
        }
        if probe_http_status(anchor, &url).await? == Some(config.readiness_status) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "target readiness {} did not return HTTP {} within {} seconds",
                config.readiness_path,
                config.readiness_status,
                config.startup_timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn probe_http_status(anchor: &str, url: &str) -> Result<Option<u16>> {
    let output = tokio::time::timeout(
        PROBE_TIMEOUT,
        Command::new("docker")
            .args([
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--network",
                &format!("container:{anchor}"),
                "--user",
                crate::TRAFFIC_PROCESS_USER,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                crate::network_probe::IMAGE,
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--max-time",
                "2",
                url,
            ])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .context("target readiness probe timed out")?
    .context("failed to run target readiness probe")?;
    if !output.status.success() {
        return Ok(None);
    }
    let status = String::from_utf8(output.stdout)
        .context("target readiness probe returned non-UTF-8 output")?;
    Ok(status.trim().parse::<u16>().ok())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[tokio::test]
    #[ignore = "requires Docker and an explicit TRAFFIC_E2E_TARGET_SMOKE_ROOT fixture"]
    async fn validates_a_real_target_image_lifecycle() {
        let target_root = PathBuf::from(
            std::env::var_os("TRAFFIC_E2E_TARGET_SMOKE_ROOT")
                .expect("TRAFFIC_E2E_TARGET_SMOKE_ROOT is required"),
        );
        let result = run_preflight(TargetContainerConfig {
            dockerfile: target_root.join(super::super::TARGET_DOCKERFILE_RELATIVE),
            startup: crate::startup::StartupConfig::default(),
            target_root,
            port: 38_181,
            readiness_path: "/healthz".to_string(),
            readiness_status: 404,
            startup_timeout: Duration::from_secs(60),
            breeze_enabled: false,
        })
        .await
        .unwrap();

        assert_eq!(result.status, "passed");
        assert!(result.checks.graceful_shutdown);
        assert!(result.checks.cleanup);
    }
}
