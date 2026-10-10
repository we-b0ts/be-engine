//! Standalone Source/Recorder service with optional gateway coordination.

mod coordination;
mod options;
mod proxy;
mod source;
#[cfg(test)]
mod tests;
pub use options::{CoordinationBackend, RecordOptions};

use self::source as process;
use crate::{
    AppState, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
use anyhow::{Context, Result, bail, ensure};
use std::{path::Path, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
};
use tracing::{info, warn};

/// Initializes Recorder and Source, registers only after readiness, and serves
/// until shutdown or loss of either the Source process or registration lease.
pub async fn run(options: RecordOptions) -> Result<()> {
    ensure!(
        crate::local_interception::effective_uid() != crate::TRAFFIC_PROCESS_UID,
        "recording service controller cannot use the reserved Source UID"
    );
    ensure!(
        options.no_interception || crate::local_interception::effective_uid() == 0,
        "recording service with interception requires a root controller"
    );
    process::prepare_fixed_identity()?;
    let config = options.config()?;
    if let Some(path) = &options.config_path {
        info!(path = %path.display(), case_path_patterns = config.http_gateway.case_path_patterns.len(),
            post_ready_settle_ms = config.recording.post_ready_settle_ms,
            post_ready_max_wait_ms = config.recording.post_ready_max_wait_ms,
            "recording service project Recorder configuration loaded");
    }
    if let Some(path) = &options.source_traffic_policy {
        info!(
            path = %path.display(),
            case_path_patterns = config.http_gateway.case_path_patterns.len(),
            "recording service source traffic policy loaded"
        );
    }
    let coordination = coordination::Coordination::connect(&options).await?;
    let program =
        process::resolve_source_program(&options.source_command[0], &options.source_workdir)?;
    process::verify_fixed_identity_access(&options.source_workdir, &program)?;
    let runtime = process::RuntimeDirectory::create(&options.data_root)?;
    let state = AppState::new_with_recording_apis_and_artifact_owner(
        config.clone(),
        options.run_id.clone(),
        Vec::new(),
        Some(options.storage_owner()?),
    )
    .await?;
    let guard = if options.no_interception {
        None
    } else {
        Some(crate::local_interception::Guard::enable(
            crate::local_interception::DnsConfig {
                dns_ip: config.dns_mock.listen.ip().to_string(),
                dns_port: config.dns_mock.listen.port(),
            },
            crate::local_interception::FakeIpConfig {
                fake_cidr: config.dns_mock.fake_cidr.clone(),
                tcp_port: config.tcp_gateway.listen.port(),
                udp_port: config.udp_gateway.listen.port(),
                tcp: true,
                udp: config.udp_gateway.enabled,
            },
        )?)
    };
    let control = runtime.path.join("recorder.sock");
    let (stop_recorder, stopped_recorder) = oneshot::channel();
    let mut recorder = tokio::spawn(state.clone().run_until(Some(control.clone()), async {
        let _ = stopped_recorder.await;
        Ok(())
    }));
    let relay = proxy::Relay::new(
        coordination.reservations.clone(),
        format!("http://{}", options.recorder_listen).parse()?,
        options.scope.clone(),
        Duration::from_millis(config.http_gateway.request_timeout_ms),
        config.recording.max_body_bytes,
    );
    let (stop_adapter, adapter_stopped) = watch::channel(false);
    let mut source = None;
    let mut adapter = None;
    let mut recorder_finished = false;
    let mut adapter_finished = false;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let result = async {
        tokio::select! {
            ready = wait_startup(&control, options.startup_timeout_seconds, false, &mut recorder, &mut recorder_finished) => ready?,
            signal = &mut shutdown => { signal?; return Ok(()); }
        }
        source::verify_sensitive_state_isolated(&options.data_root, &options.data_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT).join("recordings"), &config.tls.ca_key_path)?;
        let trust = process::prepare_source_trust(&runtime.path, &config.tls.ca_cert_path, &options.source_workdir, &program)?;
        source = Some(process::spawn_source(&program, &options.source_command[1..], &options.source_workdir, &trust)?);
        let source = source.as_mut().unwrap();
        tokio::select! {
            ready = wait_startup(&control, options.startup_timeout_seconds, true, &mut recorder, &mut recorder_finished) => ready?,
            status = source.wait() => bail!("Source exited during startup: {}", status?),
            signal = &mut shutdown => { signal?; return Ok(()); }
        }
        let listener = TcpListener::bind(options.listen).await?;
        adapter = Some(tokio::spawn(proxy::serve(listener, relay.clone(), adapter_stopped)));
        // Cleanup always tries token-checked unregister, even if SET timed out.
        coordination.register().await?;
        relay.open();
        info!(listen = %options.listen, run_id = %state.recorder().run_dir.file_name().unwrap().to_string_lossy(),
            manifest = %state.recorder().run_dir.join("recording-run.json").display(),
            coordination = ?options.coordination, "recording ready; waiting for requests");
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        heartbeat.tick().await;
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; break Ok(()); }
                status = source.wait() => break Err(anyhow::anyhow!("Source exited: {}", status?)),
                result = &mut recorder => { recorder_finished = true; result.context("Recorder task failed")??; break Err(anyhow::anyhow!("Recorder stopped unexpectedly")); }
                result = adapter.as_mut().unwrap() => { adapter_finished = true; result.context("adapter task failed")??; break Err(anyhow::anyhow!("adapter stopped unexpectedly")); }
                _ = heartbeat.tick() => { coordination.renew().await?; }
            }
        }
    }.await;
    relay.close();
    if let Err(error) = coordination.unregister().await {
        warn!(%error, "recorder unregister failed; address TTL will expire");
    }
    let _ = stop_adapter.send(true);
    if tokio::time::timeout(Duration::from_secs(60), relay.drain())
        .await
        .is_err()
    {
        warn!("recording service request drain timed out");
    }
    let _ = stop_recorder.send(());
    let recorder_cleanup = if recorder_finished {
        Ok(())
    } else {
        match tokio::time::timeout(Duration::from_secs(180), &mut recorder).await {
            Ok(result) => result
                .context("Recorder task failed during shutdown")
                .and_then(|result| result),
            Err(_) => {
                recorder.abort();
                Err(anyhow::anyhow!("Recorder finalization timed out"))
            }
        }
    };
    let source_cleanup = if let Some(source) = &mut source {
        process::stop_source(source).await
    } else {
        Ok(())
    };
    if let Some(mut adapter) = adapter
        && !adapter_finished
        && tokio::time::timeout(Duration::from_secs(5), &mut adapter)
            .await
            .is_err()
    {
        adapter.abort();
    }
    drop(guard);
    result?;
    recorder_cleanup?;
    source_cleanup?;
    let manifest = state.recorder().run_dir.join("recording-run.json");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest)?)?;
    ensure!(
        report["status"] == "completed"
            && report["failed_cases"] == 0
            && report["errors"].as_array().is_some_and(Vec::is_empty),
        "recording finalized with errors; inspect {}",
        manifest.display()
    );
    crate::command_output::stdout_line(format_args!(
        "{}",
        serde_json::json!({
            "status": "completed", "run_id": report["run_id"], "manifest": manifest,
            "published_cases": report["published_cases"]
        })
    ))
}

async fn wait_startup(
    control: &Path,
    seconds: u64,
    ready: bool,
    recorder: &mut tokio::task::JoinHandle<Result<()>>,
    recorder_finished: &mut bool,
) -> Result<()> {
    let config = RecordingWaitConfig {
        control_socket_path: control.to_owned(),
        timeout: Duration::from_secs(seconds),
    };
    let wait = async {
        if ready {
            wait_for_recording_ready(config).await
        } else {
            wait_for_recording_listeners(config).await
        }
    };
    tokio::select! {
        result = wait => { result?; Ok(()) }
        result = recorder => { *recorder_finished = true; result.context("Recorder startup task failed")??; bail!("Recorder exited before startup completed") }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
