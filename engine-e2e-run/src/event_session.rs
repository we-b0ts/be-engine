//! Managed regression of one sealed, globally ordered Source recording.

mod api_progress;
mod control;
mod http;
mod state;
mod target;

pub use state::{event_session_report, status_e2e_event_session};

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::process::Child;
use traffic_engine_e2e_contract::{
    E2eEventSessionApiProgress, E2eEventSessionCaseProgress, E2eEventSessionPhase,
};
use traffic_engine_evidence::session::SessionApiCounts;
use traffic_model::{
    session::{ENGINE_SHUTDOWN_CANCEL_REASON, SessionEvent},
    trace::RecordedEvent,
};
use traffic_recording_store::session::{self, ReplayEvent, ReplayEvents};
use uuid::Uuid;

use self::{api_progress::ApiProgress, control::SessionControl, http::Http, target::Target};
use super::{
    E2eEventSessionOptions, E2eEventSessionProgress, E2eEventSessionResult, E2eEventSessionState,
    E2eEventSessionStatus,
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout, RunStatus},
    run_config, runtime, store,
};
use crate::replay_timer::{self, ManagedTimer};

pub async fn run_e2e_event_session(
    options: E2eEventSessionOptions,
) -> Result<E2eEventSessionResult> {
    let (result, _) = run_e2e_event_session_with_apis(options).await?;
    Ok(result)
}

pub async fn run_e2e_event_session_with_apis(
    options: E2eEventSessionOptions,
) -> Result<(E2eEventSessionResult, BTreeMap<String, SessionApiCounts>)> {
    let (config, mut layout) = run_config::resolve_session_layout(
        &options.target_root,
        &options.recording_root,
        options.run_key.as_deref(),
    )?;
    let _guard = lock(&layout.internal_root)?;
    ensure!(
        !layout.active_dir.exists() && store::focused_active_directories(&layout)?.is_empty(),
        "the recording already has an active Case Replay attempt"
    );
    let attempt_id = Uuid::new_v4();
    let target_inputs = options
        .expected_target_commit
        .as_deref()
        .map(|commit| candidate_inputs(&layout.target_root, commit))
        .transpose()?;
    let attempts = state::attempts_root(&layout.run_root, &layout.case_source);
    layout.run_root = attempts.join(attempt_id.simple().to_string());
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
        attempt_id: attempt_id.simple().to_string(),
        recording_root: layout.case_source.clone(),
        target_commit: options.expected_target_commit,
        target_inputs,
        engine_revision: Some(crate::build_info::ENGINE_FINGERPRINT.to_owned()),
        target_image_id: None,
        passed: false,
        events: E2eEventSessionProgress::default(),
        phase: E2eEventSessionPhase::PreparingReplay,
        apis: E2eEventSessionApiProgress::default(),
        cases: E2eEventSessionCaseProgress::default(),
        error: None,
        progress: layout.run_root.join(state::PROGRESS),
        report: state.replay_report.clone(),
    };
    let _attempt = state::begin(&attempts, attempt_id, &result)?;
    let mut api_counts = BTreeMap::new();
    let outcome = async {
        let recording = layout.case_source.clone();
        let target = layout.target_root.clone();
        let (tape, mut apis) = tokio::task::spawn_blocking(move || {
            let apis = ApiProgress::load(&target, &recording)?;
            // SAFETY: Replay leaves the sealed segments unchanged while the
            // reader and delivery slices are live.
            let tape = unsafe { session::read_for_replay(&recording) }?;
            Ok::<_, anyhow::Error>((tape, apis))
        })
        .await
        .context("session recording reader task failed")??;
        result.apis = apis.status();
        result.cases = apis.case_status();
        state::publish_progress(&result)?;
        let replay = run(&config, &layout, state, tape, &mut result, &mut apis).await;
        api_counts = apis.into_counts();
        replay?;
        if let (Some(commit), Some(inputs)) = (&result.target_commit, &result.target_inputs) {
            ensure!(
                &candidate_inputs(&layout.target_root, commit)? == inputs,
                "Target inputs changed during Replay; verify the candidate again"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = outcome {
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
    if result.passed {
        result.phase = E2eEventSessionPhase::Complete;
    }
    state::finish(&layout.run_root, &result)?;
    Ok((result, api_counts))
}

fn candidate_inputs(root: &Path, commit: &str) -> Result<String> {
    let head = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .context("read Target HEAD for event Replay")?;
    ensure!(
        head.status.success() && std::str::from_utf8(&head.stdout)?.trim() == commit,
        "Target HEAD does not match the Replay candidate {commit}"
    );
    ensure!(
        crate::execution_identity::matches_revision(root, commit)?,
        "Target code differs from the Replay candidate {commit}; commit the intended changes first"
    );
    crate::execution_identity::repository_fingerprint(root)
}

fn lock(root: &Path) -> Result<state::ReplayLock> {
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
    Ok(state::ReplayLock(file))
}

async fn run(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    mut state: ActiveRunState,
    tape: ReplayEvents,
    result: &mut E2eEventSessionResult,
    apis: &mut ApiProgress,
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
        publish_result_progress(
            control.status().await?,
            E2eEventSessionPhase::Building,
            apis.status(),
            apis.case_status(),
            result,
        )?;
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
    result.target_image_id = Some(image.id.clone());
    let mut target = Target::new(state, config, layout, image, timer.as_ref(), &ca);
    let live = Mutex::new(DriverProgress {
        phase: E2eEventSessionPhase::StartingTarget,
        apis,
    });
    let mut outcome = drive(config, layout, &control, &mut target, tape, result, &live).await;
    let DriverProgress { phase, apis } = live.into_inner().expect("Replay driver progress");
    if let Ok(progress) = control.status().await {
        outcome = outcome.and(publish_result_progress(
            progress,
            phase,
            apis.status(),
            apis.case_status(),
            result,
        ));
    } else {
        result.phase = phase;
        result.apis = apis.status();
        result.cases = apis.case_status();
    }
    let complete = result.events.complete
        && result.events.failure.is_none()
        && result.events.matched > 0
        && result.events.total == Some(result.events.matched);
    if outcome.is_ok() && !complete {
        outcome = Err(anyhow::anyhow!("recorded event session did not complete"));
    }
    if outcome.is_ok() && result.apis.total != Some(result.apis.verified) {
        outcome = Err(anyhow::anyhow!(
            "passing session does not cover every recorded API exchange"
        ));
    }
    if let Err(error) = &outcome {
        if !error.is::<SourceEventRead>()
            && result.events.failure.is_none()
            && let Some(sequence) = expected_sequence(&result.events)
        {
            let _ = control.fail(sequence, &short_error(error)).await;
            if let Ok(progress) = control.status().await {
                let _ = publish_result_progress(
                    progress,
                    result.phase,
                    apis.status(),
                    apis.case_status(),
                    result,
                );
            }
        }
        target.stop_after_failure().await;
    }
    if outcome.is_ok() {
        result.phase = E2eEventSessionPhase::Finalizing;
        outcome = state::publish_progress(result);
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
    tape: ReplayEvents,
    result: &mut E2eEventSessionResult,
    live: &Mutex<DriverProgress<'_>>,
) -> Result<()> {
    result.phase = E2eEventSessionPhase::StartingTarget;
    state::publish_progress(result)?;
    let mut http = Http::new(config, &layout.case_source, &layout.target_root)?;
    let execution = run_events(config, control, target, &mut http, tape, live);
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
                let (phase, apis, cases) = {
                    let live = live.lock().expect("Replay driver progress");
                    (live.phase, live.apis.status(), live.apis.case_status())
                };
                publish_result_progress(progress, phase, apis, cases, result)?;
                ensure!(!failed, "event regression stopped at its first mismatch");
            }
        }
    }
}

struct DriverProgress<'a> {
    phase: E2eEventSessionPhase,
    apis: &'a mut ApiProgress,
}

#[derive(Debug)]
struct SourceEventRead;

impl fmt::Display for SourceEventRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cannot read recorded primary events")
    }
}

async fn run_events(
    config: &ResolvedProjectConfig,
    control: &SessionControl,
    target: &mut Target<'_>,
    http: &mut Http<'_>,
    tape: ReplayEvents,
    live: &Mutex<DriverProgress<'_>>,
) -> Result<()> {
    // Read storage off the async executor. Delivery owns only the current
    // event and this small queue of subsequent events.
    let (send, mut pending) = tokio::sync::mpsc::channel(8);
    let reader = tokio::task::spawn_blocking(move || {
        for event in tape {
            if send.blocking_send(event).is_err() {
                break;
            }
        }
    });
    while let Some(event) = pending.recv().await {
        let RecordedEvent {
            sequence, event, ..
        } = event.context(SourceEventRead)?;
        control.wait(sequence).await?;
        let handling = apply(config, control, sequence, target, http, event, live).await;
        if let Err(error) = handling {
            if let Err(publication) = control.fail(sequence, &short_error(&error)).await {
                tracing::warn!(%publication, sequence, "failed to publish first Replay event failure");
            }
            return Err(error)
                .with_context(|| format!("event Replay failed at sequence {sequence}"));
        }
    }
    reader.await.context(SourceEventRead)?;
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
    event: ReplayEvent,
    live: &Mutex<DriverProgress<'_>>,
) -> Result<()> {
    let event = match event {
        ReplayEvent::Event(event) => event,
        ReplayEvent::ResponsePart {
            exchange,
            part,
            data,
        } => {
            http.part(exchange, part, &data).await?;
            return control.commit(sequence).await;
        }
    };
    let completed = match event {
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
            live.lock().expect("Replay driver progress").phase = E2eEventSessionPhase::Replaying;
            return Ok(());
        }
        SessionEvent::Stop => {
            control.commit(sequence).await?;
            return target.stop().await;
        }
        SessionEvent::SourceExit {
            status,
            forced_by_recorder,
        } => {
            target.exited(status, forced_by_recorder).await?;
            None
        }
        SessionEvent::PrimaryRequest { exchange, request } => {
            let api = live
                .lock()
                .expect("Replay driver progress")
                .apis
                .identify(&request)?;
            let prepared = http.prepare(&request)?;
            control.commit(sequence).await?;
            http.start(exchange, request, prepared)?;
            live.lock()
                .expect("Replay driver progress")
                .apis
                .start(exchange, api);
            return Ok(());
        }
        SessionEvent::PrimaryResponseHeaders { exchange, response } => {
            http.headers(exchange, response).await?;
            None
        }
        SessionEvent::PrimaryResponsePart { .. } => {
            bail!("encoded primary response part entered the Replay driver")
        }
        SessionEvent::PrimaryResponseTrailers { exchange, trailers } => {
            http.trailers(exchange, trailers).await?;
            None
        }
        SessionEvent::PrimaryResponseEnd { exchange } => {
            http.end(exchange).await?;
            Some(exchange)
        }
        SessionEvent::PrimaryCancel { exchange, reason } => {
            if matches!(
                reason.as_str(),
                "client_cancelled" | ENGINE_SHUTDOWN_CANCEL_REASON
            ) {
                http.admits_disconnect(exchange)?;
                control.commit(sequence).await?;
                http.cancel(exchange, &reason).await?;
                return live
                    .lock()
                    .expect("Replay driver progress")
                    .apis
                    .finish(exchange);
            }
            http.cancel(exchange, &reason).await?;
            Some(exchange)
        }
    };
    control.commit(sequence).await?;
    if let Some(exchange) = completed {
        live.lock()
            .expect("Replay driver progress")
            .apis
            .finish(exchange)?;
    }
    Ok(())
}

fn publish_result_progress(
    progress: E2eEventSessionProgress,
    phase: E2eEventSessionPhase,
    apis: E2eEventSessionApiProgress,
    cases: E2eEventSessionCaseProgress,
    result: &mut E2eEventSessionResult,
) -> Result<()> {
    if result.events != progress
        || result.phase != phase
        || result.apis != apis
        || result.cases != cases
    {
        tracing::info!(
            matched = progress.matched,
            total = ?progress.total,
            last_sequence = progress.last_sequence,
            ?phase,
            verified_apis = apis.verified,
            total_apis = ?apis.total,
            completed_cases = cases.completed,
            total_cases = ?cases.total,
            "event regression progress"
        );
        result.events = progress;
        result.phase = phase;
        result.apis = apis;
        result.cases = cases;
        state::publish_progress(result)?;
    }
    Ok(())
}

fn short_error(error: &anyhow::Error) -> String {
    let message = if error.is::<SourceEventRead>() {
        format!("{error:#}")
    } else {
        error.to_string()
    };
    message.chars().take(600).collect()
}
