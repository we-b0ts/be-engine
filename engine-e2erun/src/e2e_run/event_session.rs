//! Managed regression of one sealed, globally ordered Source recording.

mod control;
mod http;
mod target;

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Child;
use traffic_model::{
    session::{ENGINE_SHUTDOWN_CANCEL_REASON, SessionEvent},
    trace::RecordedEvent,
};
use uuid::Uuid;

use self::{control::SessionControl, http::Http, target::Target};
use super::{
    E2eEventSessionOptions, E2eEventSessionProgress, E2eEventSessionResult, config,
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout, RunStatus},
    runtime, store,
};
use crate::replay_timer::{self, ManagedTimer};

pub async fn run_e2e_event_session(
    options: E2eEventSessionOptions,
) -> Result<E2eEventSessionResult> {
    let (config, mut layout) = config::resolve_session_layout(
        &options.target_root,
        &options.recording_root,
        options.run_key.as_deref(),
    )?;
    let recording = layout.case_source.clone();
    let tape =
        tokio::task::spawn_blocking(move || traffic_recording_store::session::read(&recording))
            .await
            .context("session recording reader task failed")??;
    let _guard = lock(&layout.internal_root)?;
    ensure!(
        !layout.active_dir.exists() && store::focused_active_directories(&layout)?.is_empty(),
        "the recording already has an active Case Replay attempt"
    );
    let attempt_id = Uuid::new_v4().simple().to_string();
    layout.run_root = layout.run_root.join("event-sessions").join(&attempt_id);
    layout.active_dir = layout.run_root.join(".active");
    let state = ActiveRunState::for_runtime(
        layout.run_key.clone(),
        1,
        layout.case_source.clone(),
        &layout.active_dir,
    );
    store::begin_active(&layout, &state)?;
    let mut result = E2eEventSessionResult {
        run_key: layout.run_key.clone(),
        attempt_id,
        recording_root: layout.case_source.clone(),
        passed: false,
        events: E2eEventSessionProgress::default(),
        error: None,
        progress: layout.run_root.join("event-progress.json"),
        report: state.replay_report.clone(),
    };
    let result_path = layout.run_root.join("event-result.json");
    store::write_json(&result.progress, &result.events)?;
    if let Err(error) = run(&config, &layout, state, tape, &mut result).await {
        result.error = Some(
            if let Some(reason) = result
                .events
                .failure
                .as_ref()
                .and_then(|failure| failure["reason"].as_str())
            {
                reason.to_owned()
            } else {
                short_error(&error)
            },
        );
    }
    result.passed = result.error.is_none() && result.events.complete;
    store::write_json(&result.progress, &result.events)?;
    store::write_json(&result_path, &result)?;
    Ok(result)
}

fn lock(root: &Path) -> Result<fs::File> {
    fs::create_dir_all(root)?;
    let path = root.join("event-replay.lock");
    let file = fs::File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.try_lock()
        .context("another event regression is active for this Target")?;
    Ok(file)
}

async fn run(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    mut state: ActiveRunState,
    tape: Vec<RecordedEvent<SessionEvent>>,
    result: &mut E2eEventSessionResult,
) -> Result<()> {
    let plan = replay_timer::read_plan(&layout.target_root, config.replay_stream_timing)?;
    let timer = plan.as_deref().map(ManagedTimer::stage).transpose()?;
    let mut replay = runtime::spawn_event_replay(config, layout, &state, timer.as_ref())?;
    state.replay_pid = replay.id();
    if let Err(error) = store::write_active(layout, &state) {
        runtime::stop_replay_process(&mut state, &mut replay).await;
        return Err(error);
    }
    let (control, ca) = match ready(config, layout, &mut state, &mut replay).await {
        Ok(ready) => ready,
        Err(error) => {
            runtime::stop_replay_process(&mut state, &mut replay).await;
            return Err(error);
        }
    };
    let image = match async {
        publish_result_progress(result, control.status().await?)?;
        runtime::build_target_image(config, layout, timer.is_some()).await
    }
    .await
    {
        Ok(image) => image,
        Err(error) => {
            runtime::stop_replay_process(&mut state, &mut replay).await;
            return Err(error);
        }
    };
    let mut target = Target::new(state, config, layout, image, timer.as_ref(), &ca);
    let mut outcome = drive(config, layout, &control, &mut target, tape, result).await;
    if let Ok(progress) = control.status().await {
        outcome = outcome.and(publish_result_progress(result, progress));
    }
    let complete = result.events.complete
        && result.events.failure.is_none()
        && result.events.total > 0
        && result.events.matched == result.events.total;
    if outcome.is_ok() && !complete {
        outcome = Err(anyhow::anyhow!("recorded event session did not complete"));
    }
    if let Err(error) = &outcome {
        if result.events.failure.is_none()
            && let Some(sequence) = expected_sequence(&result.events)
        {
            let _ = control.fail(sequence, &short_error(error)).await;
            if let Ok(progress) = control.status().await {
                let _ = publish_result_progress(result, progress);
            }
        }
        target.stop_after_failure().await;
    }
    let strict = outcome.is_ok();
    let finalized = tokio::time::timeout(
        config.replay_startup_timeout,
        runtime::control(&target.state, "finalize", None, strict, strict),
    )
    .await
    .context("event Replay did not finalize before its deadline")
    .and_then(std::convert::identity);
    if outcome.is_ok() {
        outcome = finalized.and_then(|response| {
            ensure!(
                response["finalized"] == true,
                "event Replay did not publish final evidence"
            );
            Ok(())
        });
    }
    if outcome.is_ok() {
        outcome = runtime::wait_for_replay(&mut replay).await;
    }
    let status = if outcome.is_ok() {
        RunStatus::Successful
    } else {
        RunStatus::Failed
    };
    target.state.status = status;
    target.state.finished_at = Some(chrono::Utc::now());
    target.cleanup(&mut replay).await;
    outcome
}

async fn ready(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    state: &mut ActiveRunState,
    replay: &mut Child,
) -> Result<(SessionControl, PathBuf)> {
    let response = tokio::select! {
        response = runtime::wait_for_replay_ready(state, config.replay_startup_timeout) => response?,
        status = replay.wait() => bail!("{}", runtime::replay_startup_failure(layout, status?).await),
    };
    state.session_id = response
        .pointer("/session/session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    ensure!(
        state.session_id.is_some(),
        "event Replay session has no identity"
    );
    let control = SessionControl::from_session(&state.replay_session).await?;
    Ok((control, runtime::replay_ca_cert_path(&response)?))
}

async fn drive(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    control: &SessionControl,
    target: &mut Target<'_>,
    tape: Vec<RecordedEvent<SessionEvent>>,
    result: &mut E2eEventSessionResult,
) -> Result<()> {
    let mut http = Http::new(config, &layout.case_source, &layout.target_root)?;
    let execution = run_events(config, control, target, &mut http, tape);
    tokio::pin!(execution);
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let interrupted = tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    loop {
        tokio::select! {
            outcome = &mut execution => return outcome,
            signal = &mut interrupted => {
                signal.context("could not receive event regression interruption signal")?;
                bail!("event regression interrupted");
            }
            _ = tick.tick() => {
                let progress = control.status().await?;
                let failed = progress.failure.is_some();
                publish_result_progress(result, progress)?;
                ensure!(!failed, "event regression stopped at its first mismatch");
            }
        }
    }
}

async fn run_events(
    config: &ResolvedProjectConfig,
    control: &SessionControl,
    target: &mut Target<'_>,
    http: &mut Http<'_>,
    tape: Vec<RecordedEvent<SessionEvent>>,
) -> Result<()> {
    for RecordedEvent {
        sequence, event, ..
    } in tape
    {
        control.wait(sequence).await?;
        let handling = apply(config, control, sequence, target, http, event).await;
        if let Err(error) = handling {
            if let Err(publication) = control.fail(sequence, &short_error(&error)).await {
                tracing::warn!(%publication, sequence, "failed to publish first Replay event failure");
            }
            return Err(error)
                .with_context(|| format!("event Replay failed at sequence {sequence}"));
        }
    }
    ensure!(
        http.is_empty(),
        "event Replay ended with unclosed primary HTTP exchanges"
    );
    ensure!(
        !target.state.target_started,
        "event Replay ended without observing Target shutdown"
    );
    wait_for_dependency_tail(control, config.replay_case_no_progress_timeout).await
}

async fn wait_for_dependency_tail(control: &SessionControl, budget: Duration) -> Result<()> {
    let mut last_sequence = None;
    let mut due = tokio::time::Instant::now() + budget;
    loop {
        let progress = control.status().await?;
        ensure!(
            progress.failure.is_none(),
            "recorded dependency tail failed"
        );
        if progress.complete {
            return Ok(());
        }
        if progress.last_sequence != last_sequence {
            last_sequence = progress.last_sequence;
            due = tokio::time::Instant::now() + budget;
        }
        if tokio::time::Instant::now() >= due {
            let reason = "recorded dependency did not terminate after Target shutdown";
            if let Some(sequence) = expected_sequence(&progress) {
                let _ = control.fail(sequence, reason).await;
            }
            bail!(reason);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn expected_sequence(progress: &E2eEventSessionProgress) -> Option<u64> {
    progress
        .expected
        .as_ref()
        .and_then(|expected| expected["sequence"].as_u64())
}

async fn apply(
    config: &ResolvedProjectConfig,
    control: &SessionControl,
    sequence: u64,
    target: &mut Target<'_>,
    http: &mut Http<'_>,
    event: SessionEvent,
) -> Result<()> {
    match event {
        SessionEvent::SourceStart => {
            control.commit(sequence).await?;
            return target.start().await;
        }
        SessionEvent::Ready => {
            ensure!(
                !config.target_http_readiness_enabled || http.ready_probe_seen(),
                "Target has no matching recorded HTTP readiness probe"
            );
            control.commit(sequence).await?;
            target.ready();
            return Ok(());
        }
        SessionEvent::Stop => {
            control.commit(sequence).await?;
            return target.stop().await;
        }
        SessionEvent::SourceExit { status } => target.exited(status).await?,
        SessionEvent::PrimaryRequest { exchange, request } => {
            let prepared = http.prepare(&request)?;
            control.commit(sequence).await?;
            return http.start(exchange, request, prepared);
        }
        SessionEvent::PrimaryResponseHeaders { exchange, response } => {
            http.headers(exchange, response).await?
        }
        SessionEvent::PrimaryResponsePart {
            exchange,
            part,
            data_base64,
        } => http.part(exchange, part, &data_base64).await?,
        SessionEvent::PrimaryResponseTrailers { exchange, trailers } => {
            http.trailers(exchange, trailers).await?
        }
        SessionEvent::PrimaryResponseEnd { exchange } => http.end(exchange).await?,
        SessionEvent::PrimaryCancel { exchange, reason } => {
            if matches!(
                reason.as_str(),
                "client_cancelled" | ENGINE_SHUTDOWN_CANCEL_REASON
            ) {
                http.admits_disconnect(exchange)?;
                control.commit(sequence).await?;
                return http.cancel(exchange, &reason).await;
            }
            http.cancel(exchange, &reason).await?;
        }
    }
    control.commit(sequence).await
}

fn publish_result_progress(
    result: &mut E2eEventSessionResult,
    progress: E2eEventSessionProgress,
) -> Result<()> {
    if result.events != progress {
        tracing::info!(
            matched = progress.matched,
            total = progress.total,
            last_sequence = progress.last_sequence,
            "event regression progress"
        );
        result.events = progress;
        store::write_json(&result.progress, &result.events)?;
    }
    Ok(())
}

fn short_error(error: &anyhow::Error) -> String {
    error.to_string().chars().take(600).collect()
}
