//! Standalone Source/Recorder service with optional gateway coordination.

mod api_policy;
mod coordination;
mod identity;
mod kubernetes;
mod options;
mod proxy;
mod shutdown;
mod source;
#[cfg(test)]
mod tests;
pub use options::{CoordinationBackend, RecordOptions};

use self::source as process;
use crate::recording_completion::RecordingCompletionReason;
use crate::{
    AppState, RecordingWaitConfig, wait_for_recording_listeners, wait_for_recording_ready,
};
use anyhow::{Context, Result, bail, ensure};
use std::{future::Future, path::Path, pin::Pin, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
};
use tracing::{info, warn};
use traffic_model::session::SessionEvent;

/// Initializes Recorder and Source, advertises after readiness, and serves
/// independently of best-effort address registration.
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
    let api_policy = options.load_api_policy()?;
    if let Some(path) = &options.config_path {
        info!(path = %path.display(), case_path_patterns = config.http_gateway.case_path_patterns.len(),
            post_ready_settle_ms = config.recording.post_ready_settle_ms,
            post_ready_max_wait_ms = config.recording.post_ready_max_wait_ms,
            "recording service project Recorder configuration loaded");
    }
    if let Some(path) = &options.policy {
        info!(
            path = %path.display(),
            case_path_patterns = config.http_gateway.case_path_patterns.len(),
            "recording service unified policy Source projection loaded"
        );
    }
    let mut forwards = kubernetes::PortForwards::default();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let prepared = tokio::select! {
        result = forwards.prepare(&config, Duration::from_secs(options.startup_timeout_seconds)) => result.map(|()| true),
        signal = &mut shutdown => signal.map(|()| false),
    };
    let result = match prepared {
        Ok(true) => {
            run_prepared(
                options,
                config,
                api_policy,
                &mut forwards,
                shutdown.as_mut(),
            )
            .await
        }
        Ok(false) => Ok(()),
        Err(error) => Err(error),
    };
    let cleanup = forwards.shutdown().await;
    result?;
    cleanup
}

async fn run_prepared(
    options: RecordOptions,
    config: crate::AppConfig,
    api_policy: Option<api_policy::ApiPolicy>,
    forwards: &mut kubernetes::PortForwards,
    mut shutdown: Pin<&mut impl Future<Output = Result<()>>>,
) -> Result<()> {
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
    state.install_recording_upstreams(forwards.routes.clone())?;
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
    let (stop_recorder, stopped_recorder) = oneshot::channel::<Result<RecordingCompletionReason>>();
    let mut recorder = tokio::spawn(state.clone().run_until_completion(
        Some(control.clone()),
        async {
            stopped_recorder
                .await
                .unwrap_or(Ok(RecordingCompletionReason::SourceIsolationRequired))
        },
    ));
    let relay = proxy::Relay::new(
        coordination.reservations.clone(),
        format!("http://{}", options.recorder_listen).parse()?,
        options.scope.clone(),
        Duration::from_millis(config.http_gateway.request_timeout_ms),
        config.recording.max_body_bytes,
    );
    let relay = if state.session_events() {
        relay.with_session_events(state.clone())
    } else {
        relay.with_interactions(
            state.clone(),
            options
                .advertise_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:4080")
                .parse()?,
        )
    };
    let (stop_adapter, adapter_stopped) = watch::channel(false);
    let mut source = None;
    let mut adapter = None;
    let mut recorder_finished = false;
    let mut adapter_finished = false;
    let mut normal_shutdown = false;
    let mut result = async {
        tokio::select! {
            ready = wait_startup(&control, options.startup_timeout_seconds, false, &mut recorder, &mut recorder_finished) => ready?,
            error = forwards.failure() => return Err(error),
            signal = &mut shutdown => { signal?; normal_shutdown = true; return Ok(()); }
        }
        source::verify_sensitive_state_isolated(&options.data_root, &options.data_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT).join("recordings"), &config.tls.ca_key_path)?;
        let trust = process::prepare_source_trust(&runtime.path, &config.tls.ca_cert_path, &options.source_workdir, &program)?;
        identity::register(&state, &program, &options.source_workdir).await?;
        if state.session_events() {
            let listener = TcpListener::bind(options.listen).await?;
            coordination.initialize_round(api_policy.as_ref()).await?;
            adapter = Some(tokio::spawn(proxy::serve(listener, relay.clone(), adapter_stopped.clone())));
            state.session_event(SessionEvent::SourceStart)?;
        }
        source = Some(process::spawn_source(&program, &options.source_command[1..], &options.source_workdir, &trust)?);
        state.inner.source_started.send_replace(true);
        let source = source.as_mut().unwrap();
        tokio::select! {
            ready = wait_startup(&control, options.startup_timeout_seconds, true, &mut recorder, &mut recorder_finished) => ready?,
            error = forwards.failure() => return Err(error),
            status = source.wait() => bail!("Source exited during startup: {}", status?),
            result = async { adapter.as_mut().expect("running session relay").await }, if adapter.is_some() => {
                adapter_finished = true;
                result.context("adapter task failed")??;
                bail!("adapter stopped unexpectedly");
            }
            signal = &mut shutdown => { signal?; normal_shutdown = true; return Ok(()); }
        }
        if adapter.is_none() {
            let listener = TcpListener::bind(options.listen).await?;
            coordination.initialize_round(api_policy.as_ref()).await?;
            adapter = Some(tokio::spawn(proxy::serve(listener, relay.clone(), adapter_stopped)));
        }
        relay.open();
        info!(listen = %options.listen, run_id = %state.recorder().run_dir.file_name().unwrap().to_string_lossy(),
            manifest = %state.recorder().run_dir.join("recording-run.json").display(),
            coordination = ?options.coordination, "recording ready; waiting for requests");
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                signal = &mut shutdown => { signal?; normal_shutdown = true; break Ok(()); }
                error = forwards.failure() => break Err(error),
                _ = state.wait_for_interaction_source_stop() => {
                    break Ok(());
                }
                _ = state.inner.active_cases.wait_for_quiescing() => {
                    warn!("recording admission closed; stopping Source and finalizing recording");
                    if state.session_events()
                        && let Some(error) = state.inner.recording_lifecycle.snapshot().error
                    {
                        bail!("session capture failed: {error}");
                    }
                    break Ok(());
                }
                status = source.wait() => break Err(anyhow::anyhow!("Source exited: {}", status?)),
                result = &mut recorder => { recorder_finished = true; result.context("Recorder task failed")??; break Err(anyhow::anyhow!("Recorder stopped unexpectedly")); }
                result = adapter.as_mut().unwrap() => { adapter_finished = true; result.context("adapter task failed")??; break Err(anyhow::anyhow!("adapter stopped unexpectedly")); }
                _ = heartbeat.tick() => { coordination.refresh_registration().await; }
            }
        }
    }.await;
    relay.close();
    state.inner.active_cases.close_admission();
    // An unacknowledged registration may still have succeeded in Redis.
    if let Err(error) = coordination.unregister().await {
        warn!(%error, "recorder unregister failed; address TTL will expire");
    }
    if normal_shutdown
        && let Err(error) = shutdown::drain(&state, &relay).await
        && result.is_ok()
    {
        result = Err(error.context("failed to persist recording shutdown diagnostics"));
    }
    state.close_interactions();
    state.begin_case_quiescing();
    let _ = stop_adapter.send(true);
    // Source exit can emit disconnect dependencies. Keep Recorder and active
    // ownership alive until the process has exited, before draining relay/cases.
    let source_cleanup = if let Some(source) = &mut source {
        let stop_receipt = if state.session_events() {
            state.session_event(SessionEvent::Stop)
        } else {
            Ok(())
        };
        let cleanup = process::stop_source(source).await;
        cleanup.and_then(|()| {
            if state.session_events() {
                use std::os::unix::process::ExitStatusExt;
                let status = source.try_wait()?.and_then(|status| {
                    status
                        .code()
                        .or_else(|| status.signal().map(|signal| 128 + signal))
                });
                state.session_event(SessionEvent::SourceExit { status })?;
                if status == Some(128 + libc::SIGKILL) {
                    let error =
                        anyhow::anyhow!("Source was killed before session shutdown completed");
                    state.fail_session_recording(&error);
                    if result.is_ok() {
                        result = Err(error);
                    }
                }
            }
            stop_receipt
        })
    } else {
        Ok(())
    };
    if source_cleanup.is_ok() && state.inner.active_cases.is_quiescing() {
        // Source has exited and cannot start more work. End retained sockets as
        // engine cleanup, so an upstream that never replies cannot strand drain.
        let reset = state.dependency_connections().reset_open_connections();
        if !reset.connections_by_protocol.is_empty() {
            warn!(connections_by_protocol = ?reset.connections_by_protocol,
                reset_errors = ?reset.errors,
                "closed retained dependency connections after Source exit");
        }
    }
    if tokio::time::timeout(Duration::from_secs(60), relay.drain())
        .await
        .is_err()
    {
        warn!("recording service request drain timed out");
    }
    if result.is_ok()
        && let Some(error) = forwards.try_failure()
    {
        result = Err(error);
    }
    if let Err(error) = forwards.shutdown().await
        && result.is_ok()
    {
        result = Err(error);
    }
    if !state.close_dependency_capture().await && result.is_ok() {
        result = Err(anyhow::anyhow!(
            "run dependency capture did not drain after Source shutdown"
        ));
    }
    let close_limit_case = state.inner.active_cases.socketio_close_limit_case();
    let completion_reason = if close_limit_case.is_some() {
        RecordingCompletionReason::SocketioCloseTailLimit
    } else if normal_shutdown {
        RecordingCompletionReason::ShutdownSignal
    } else {
        RecordingCompletionReason::SourceIsolationRequired
    };
    let recorder_shutdown = result
        .as_ref()
        .map(|()| completion_reason)
        .map_err(|error| anyhow::anyhow!("recording service failed: {error}"));
    let _ = stop_recorder.send(recorder_shutdown);
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
    let close_limit_case = close_limit_case.map(|id| state.recorder().case_label(id));
    ensure!(
        usable_recording(&report, close_limit_case.as_deref()),
        "recording finalized with errors; inspect {}",
        manifest.display()
    );
    if state.session_events() {
        let ledger = state.recorder().run_dir.join("dependency-manifest.json");
        let document: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&ledger).await?)?;
        ensure!(
            document["capture_complete"] == true,
            "Source session capture is incomplete; inspect {}",
            ledger.display()
        );
    }
    crate::command_output::stdout_line(format_args!(
        "{}",
        serde_json::json!({
            "status": "completed", "run_id": report["run_id"], "manifest": manifest,
            "published_cases": report["published_cases"],
            "failed_cases": report["failed_cases"],
            "completion_reason": report["completion_reason"]
        })
    ))
}

fn usable_recording(report: &serde_json::Value, close_limit_case: Option<&str>) -> bool {
    let Some(errors) = report["errors"].as_array() else {
        return false;
    };
    if report["status"] != "completed" {
        return false;
    }
    let Some(case_id) = close_limit_case else {
        return report["failed_cases"] == 0 && errors.is_empty();
    };
    report["published_cases"]
        .as_u64()
        .is_some_and(|count| count > 0)
        && match errors.as_slice() {
            [] => report["failed_cases"] == 0,
            [error] => {
                report["failed_cases"] == 1
                    && error["case_id"] == case_id
                    && error["reason"] == crate::active_case::SOCKETIO_CLOSE_TAIL_TIMEOUT
            }
            _ => false,
        }
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
