use std::time::{Duration, Instant};

use super::*;

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) mod case_cleanup;
mod case_execution;
pub(super) mod dependency_tail;
mod derived_input;
mod finalization;
pub(crate) use finalization::FinalizationScope;
pub(in crate::replay) mod http_input_timing;
mod identity;
pub(in crate::replay) mod input_timing;
mod native_event;
pub(crate) use derived_input::register as register_derived_input;
pub(crate) use http_input_timing::connect as http_input_timing_observer;
pub(crate) use input_timing::connect as input_timing_observer;
pub(crate) use native_event::connect as native_event_observer;
mod interaction;
mod interruption;
mod server;
mod target_stop;
pub(crate) use identity::check_response_identities;
#[cfg(test)]
pub(super) use server::handle_control_stream;
pub(super) use server::run_control_socket;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const READY_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub(super) struct ReplayControlRequest {
    pub(super) command: String,
    #[serde(default)]
    pub(super) case_id: Option<String>,
    #[serde(default)]
    pub(super) fail_on_dirty: bool,
    #[serde(default)]
    pub(super) fail_on_incomplete: bool,
    #[serde(default)]
    pub(super) identity_pairs: Vec<crate::value_contract::identities::IdentityPair>,
    #[serde(default)]
    pub(super) derived_input: Option<derived_input::Registration>,
    #[serde(default)]
    pub(super) native_event: Option<native_event::Observation>,
    #[serde(default)]
    pub(super) input_timing: Option<input_timing::Query>,
    #[serde(default)]
    pub(super) socketio_timing: Option<crate::interaction::replay::timing::SocketIoTiming>,
}

pub(crate) async fn send_control_request(config: MysqlReplayControlConfig) -> Result<Value> {
    if config.command == "wait_ready" {
        let timeout = config.wait_timeout.unwrap_or(DEFAULT_READY_TIMEOUT);
        let started = Instant::now();
        let mut next_progress = READY_PROGRESS_INTERVAL;
        tracing::info!(
            timeout_seconds = timeout.as_secs(),
            session = %config.session_path.display(),
            "waiting for replay session readiness"
        );
        loop {
            let error = match send_control_request_once(config.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => err,
            };
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(error).with_context(|| {
                    format!(
                        "replay session did not become ready within {} seconds",
                        timeout.as_secs()
                    )
                });
            }
            if elapsed >= next_progress {
                tracing::info!(
                    elapsed_seconds = elapsed.as_secs(),
                    timeout_seconds = timeout.as_secs(),
                    session = %config.session_path.display(),
                    "still waiting for replay session readiness"
                );
                next_progress += READY_PROGRESS_INTERVAL;
            }
            tokio::time::sleep(READY_POLL_INTERVAL.min(timeout.saturating_sub(elapsed))).await;
        }
    }
    send_control_request_once(config).await
}

pub(super) async fn send_control_request_once(config: MysqlReplayControlConfig) -> Result<Value> {
    let session_raw = tokio::fs::read_to_string(&config.session_path)
        .await
        .with_context(|| {
            format!(
                "failed to read replay session {}",
                config.session_path.display()
            )
        })?;
    let session: Value =
        serde_json::from_str(&session_raw).context("failed to parse replay session JSON")?;
    let control_socket = session
        .get("control_socket")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("replay session has no control_socket"))?;
    let pid = session.get("pid").and_then(Value::as_u64);
    if let Some(pid) = pid
        && !process_exists(pid)
    {
        return Err(anyhow!(
            "replay session process {pid} is not running for {}",
            config.session_path.display()
        ));
    }

    let request = serde_json::json!({
        "command": config.command,
        "case_id": config.case_id,
        "fail_on_dirty": config.fail_on_dirty,
        "fail_on_incomplete": config.fail_on_incomplete,
    });
    let mut stream = UnixStream::connect(control_socket)
        .await
        .with_context(|| format!("failed to connect replay control socket {control_socket}"))?;
    let mut payload =
        serde_json::to_vec(&request).context("failed to serialize replay control request")?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .context("failed to write replay control request")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("failed to read replay control response")?;
    let response: Value =
        serde_json::from_str(line.trim()).context("failed to parse replay control response")?;
    if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        Ok(response)
    } else {
        Err(anyhow!(control_failure_message(&response, &session)))
    }
}

fn control_failure_message(response: &Value, session: &Value) -> String {
    let mut message = response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("replay control command failed")
        .to_owned();
    for field in ["complete", "dirty", "finalized"] {
        if let Some(value) = response.get(field).and_then(Value::as_bool) {
            message.push_str(&format!("; {field}={value}"));
        }
    }
    if let Some(report_path) = session
        .get("report_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        message.push_str("; inspect replay report at ");
        message.push_str(report_path);
    }
    message
}

pub(super) fn process_exists(pid: u64) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(super) async fn handle_control_request(
    request: ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
) -> (Value, bool) {
    let command = request.command.as_str();
    let mut final_report = None;
    let response = match command {
        "wait_ready" | "status" => {
            let state = state.lock().await;
            serde_json::json!({
                "ok": true,
                "ready": true,
                "session": session_snapshot(
                    &state,
                    control_socket_path.as_ref(),
                    report_path.as_ref(),
                    true
                ),
            })
        }
        "cases" => {
            let state = state.lock().await;
            serde_json::json!({
                "ok": true,
                "cases": state.case_reports(),
                "active_case_id": state.active_case_id,
            })
        }
        "prefetch" => {
            match deferred::prefetch::enqueue(state.clone(), request.case_id.as_deref()).await {
                Ok(queued) => serde_json::json!({"ok": true, "queued": queued}),
                Err(error) => serde_json::json!({"ok": false, "error": format!("{error:#}")}),
            }
        }
        "request_begin" => {
            let mut state = state.lock().await;
            if let Some(case) = request
                .case_id
                .as_deref()
                .filter(|case| state.active_case_id.as_deref() == Some(*case))
            {
                match state
                    .replay_policy
                    .as_ref()
                    .map(|policy| policy.request_contracts.request_begin(case))
                    .transpose()
                {
                    Ok(_) => {
                        state.close_startup_phase(case);
                        let epoch = state
                            .redis
                            .request_contracts
                            .request_times(case)
                            .target
                            .unwrap_or_else(Utc::now);
                        match state
                            .redis
                            .pubsub
                            .native_clock
                            .request_begin(case, epoch)
                            .and_then(|()| {
                                state
                                    .redis
                                    .pubsub
                                    .namespace_sessions
                                    .request_begin(case, epoch)
                            }) {
                            Ok(()) => {
                                state.advance_admission_epoch();
                                serde_json::json!({"ok":true})
                            }
                            Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
                        }
                    }
                    Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
                }
            } else {
                serde_json::json!({"ok":false,"error":"request_begin requires the active case"})
            }
        }
        "begin" => begin_case(&request, state.clone()).await,
        "case_execution_status" => {
            let state = state.lock().await;
            case_execution::status(&state, request.case_id.as_deref())
        }
        "case_client_aborted" => {
            let mut state = state.lock().await;
            let result = request
                .case_id
                .as_deref()
                .context("case_client_aborted requires case_id")
                .and_then(|case| case_cleanup::mark_client_aborted(&mut state, case));
            match result {
                Ok(()) => serde_json::json!({"ok":true}),
                Err(error) => serde_json::json!({"ok":false,"error":format!("{error:#}")}),
            }
        }
        "case_failed" => {
            let mut state = state.lock().await;
            let result = request
                .case_id
                .as_deref()
                .context("case_failed requires case_id")
                .and_then(|case| case_cleanup::mark_failed(&mut state, case));
            match result {
                Ok(()) => serde_json::json!({"ok":true}),
                Err(error) => serde_json::json!({"ok":false,"error":format!("{error:#}")}),
            }
        }
        "response_identities" => identity::accept(&request, &state).await,
        "response_time_copies" => {
            let state = state.lock().await;
            if let Some(case) = request
                .case_id
                .as_deref()
                .filter(|case| state.active_case_id.as_deref() == Some(*case))
            {
                let copies = state
                    .replay_policy
                    .as_ref()
                    .map(|policy| policy.request_contracts.delivered_time_copies(case))
                    .unwrap_or_default();
                serde_json::json!({"ok":true, "time_copies":copies})
            } else {
                serde_json::json!({"ok":false, "error":"response time provenance requires the active case"})
            }
        }
        "derived_input" => derived_input::accept(&request, &state).await,
        "native_event_begin" | "native_event" | "native_connected" | "native_input_ack" => {
            native_event::accept(&request, &state).await
        }
        "input_timing_begin" | "input_timing" | "input_timing_tail" => {
            input_timing::accept(&request, &state).await
        }
        "http_input_timing_begin" | "http_input_timing_wait" | "http_input_timing_closed" => {
            http_input_timing::accept(&request, &state).await
        }
        "prepare_end" => target_stop::prepare(&request, &state).await,
        "end" => end_case(&request, state.clone()).await,
        "end_stopped" => end_case(&request, state.clone()).await,
        "report" => {
            let state = state.lock().await;
            let report = state.snapshot_report();
            let dirty = report_is_dirty(&report);
            let complete = report_is_complete(&report);
            if request.fail_on_incomplete && !complete {
                serde_json::json!({
                    "ok": false,
                    "complete": false,
                    "dirty": dirty,
                    "error": "replay report has pending or active cases",
                })
            } else if request.fail_on_dirty && dirty {
                serde_json::json!({
                    "ok": false,
                    "complete": complete,
                    "dirty": true,
                    "error": "replay report has dirty dependency evidence",
                })
            } else {
                serde_json::json!({
                    "ok": true,
                    "complete": complete,
                    "dirty": dirty,
                    "report": report,
                })
            }
        }
        "finalize" | "finalize_cases" => {
            let (response, report) = finalize_replay(&request, state.clone()).await;
            final_report = report;
            response
        }
        "interrupt" => interruption::publish(state.clone(), report_path.as_deref()).await,
        "stop" => {
            let state = state.lock().await;
            serde_json::json!({
                "ok": true,
                "stopping": true,
                "session": session_snapshot(
                    &state,
                    control_socket_path.as_ref(),
                    report_path.as_ref(),
                    false
                ),
            })
        }
        other => serde_json::json!({
            "ok": false,
            "error": format!("unknown replay control command {other}"),
        }),
    };
    let should_stop = command == "stop"
        || (matches!(command, "finalize" | "finalize_cases" | "interrupt")
            && response.get("ok").and_then(Value::as_bool).unwrap_or(false));
    let finalizing = matches!(command, "finalize" | "finalize_cases");
    if finalizing && should_stop && report_path.is_none() {
        state.lock().await.finalized_at = None;
        return (
            serde_json::json!({
                "ok": false,
                "error": "cannot finalize replay without a configured report path",
            }),
            false,
        );
    }
    if finalizing && should_stop {
        let path = report_path.expect("finalize report path checked");
        let report = final_report
            .as_mut()
            .expect("successful finalize must produce a report");
        let publication = async {
            let details = report::global_evidence::prepare(state.clone(), &path).await?;
            report["global_evidence"] = details.manifests.clone();
            write_final_report_value(path, report).await?;
            details.commit();
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = publication {
            state.lock().await.finalized_at = None;
            return (
                serde_json::json!({"ok": false, "error": format!("failed to persist replay report: {error:#}")}),
                false,
            );
        }
    }
    (response, should_stop)
}

async fn finalize_replay(
    request: &ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
) -> (Value, Option<Value>) {
    if let Err(error) = policy::request_contract::hypotheses::await_durable(&state).await {
        tracing::warn!(error=%error,"finalizing incomplete hypothesis evidence");
    }
    let mut state = state.lock().await;
    if state.mysql.has_in_flight()
        || state.redis.has_in_flight()
        || state.kafka.has_in_flight()
        || state.connect_failures.has_in_flight()
        || state.memcached.has_in_flight()
        || state.motan.has_in_flight()
        || state.http_has_in_flight()
    {
        return (
            serde_json::json!({"ok":false,"complete":false,"error":"cannot finalize Replay while dependency delivery or termination evidence is still in flight"}),
            None,
        );
    }
    let mut report = state.snapshot_report();
    let complete = report_is_complete(&report);
    let dirty = FinalizationScope::from_command(&request.command).is_dirty(&report);
    if request.fail_on_incomplete && !complete {
        return (
            serde_json::json!({
                "ok": false,
                "complete": false,
                "dirty": dirty,
                "error": "cannot finalize replay with pending or active cases",
            }),
            None,
        );
    }
    if request.fail_on_dirty && dirty {
        return (
            serde_json::json!({
                "ok": false,
                "complete": complete,
                "dirty": true,
                "error": "cannot finalize replay with dirty dependency evidence",
            }),
            None,
        );
    }
    {
        match state.target_observations.seal() {
            Ok(manifest) => report.policy_witnesses = Some(manifest),
            Err(error) => {
                return (
                    serde_json::json!({"ok":false,"error":format!("failed to seal policy witnesses: {error:#}")}),
                    None,
                );
            }
        }
    }
    let finalized_at = Utc::now();
    state.finalized_at = Some(finalized_at);
    report.finalized_at = Some(finalized_at);
    report.finalized = true;
    report.batch_reconciliation = state
        .batch_scope
        .as_ref()
        .map(|scope| scope.report(&report));
    let mut value = serde_json::to_value(report).expect("replay report must serialize");
    // Rule planners (for example MySQL response time shift) require the
    // persisted report to carry the finalized completeness verdict, so persist
    // it alongside `finalized` instead of returning it only in the response.
    value["complete"] = Value::Bool(complete);
    tracing::info!("generating Replay evidence");
    let started = Instant::now();
    let published_occurrences = report::unused_source::attach(&state, &mut value);
    let evidence_generation_ms = started.elapsed().as_millis() as u64;
    tracing::info!(
        evidence_generation_ms,
        published_occurrences,
        "generated Replay evidence"
    );
    (
        serde_json::json!({
            "ok": true,
            "complete": complete,
            "dirty": dirty,
            "finalized": true,
            "evidence_generation_ms": evidence_generation_ms,
        }),
        Some(value),
    )
}

pub(super) async fn begin_case(
    request: &ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
) -> Value {
    let Some(case_id) = request.case_id.as_deref() else {
        return serde_json::json!({"ok": false, "error": "begin requires case_id"});
    };
    let counter_reader = {
        let state = state.lock().await;
        if state.finalized_at.is_some() || state.target_session_stopped {
            return serde_json::json!({"ok":false,"error":"finalized Replay requires a fresh session"});
        }
        if state.deferred.is_some()
            && state
                .cases
                .get(case_id)
                .is_some_and(|case| case.status == ReplayCaseStatus::Ended)
        {
            return serde_json::json!({"ok": false, "error": "ended cases require a fresh Replay session"});
        }
        if !state.cases.contains_key(case_id) {
            return serde_json::json!({
                "ok": false,
                "error": format!("unknown replay case {case_id}")
            });
        }
        if let Some(active_case_id) = state.active_case_id.as_deref()
            && active_case_id != case_id
        {
            return serde_json::json!({
                "ok": false,
                "error": format!("replay case {active_case_id} is already active")
            });
        }
        (!state.egress_counter_starts.contains_key(case_id))
            .then(|| state.egress_counter_reader.clone())
            .flatten()
    };
    if let Err(error) = deferred::prepare_case(state.clone(), case_id).await {
        return serde_json::json!({"ok": false, "error": format!("case dependency preparation failed: {error:#}")});
    }
    if let Err(error) = dependency_tail::prepare(&state, case_id).await {
        return serde_json::json!({"ok": false, "error": format!("dependency-tail dependency preparation failed: {error:#}")});
    }
    let counter_start = match counter_reader {
        Some(reader) => Some(reader.sample().await),
        None => None,
    };
    let mut state = state.lock().await;
    if state.target_session_stopped || state.finalized_at.is_some() {
        return serde_json::json!({"ok":false,"error":"stopped Target requires a fresh Replay session"});
    }
    if let Some(active_case_id) = state.active_case_id.as_deref()
        && active_case_id != case_id
    {
        return serde_json::json!({
            "ok": false,
            "error": format!("replay case {active_case_id} is already active")
        });
    }
    let prepared_scope = match state.prepared_case(case_id) {
        Ok(plan) => serde_json::json!({
            "source_sha256": plan.source.sha256,
            "source_bytes": plan.source.source_bytes,
            "indexed_native_counts": {
                "http": plan.native.http.len(),
                "redis": plan.native.redis.len(),
                "mysql": plan.native.mysql.len(),
            },
            "rules":plan.rules.summary(),
        }),
        Err(error) => return serde_json::json!({"ok":false,"error":format!("{error:#}")}),
    };
    if let Some(sample) = counter_start {
        state
            .egress_counter_starts
            .entry(case_id.to_string())
            .or_insert(sample);
    }
    deferred::release_consumed_payloads(&mut state);
    if let Err(error) = dependency_tail::activate(&mut state, case_id) {
        return serde_json::json!({"ok": false, "error": format!("dependency-tail dependency activation failed: {error:#}")});
    }
    state.advance_admission_epoch();
    state.set_active_case(Some(case_id.to_string()));
    state.input_timing = None;
    if let Some(timeline) = state.http_input_timing.take() {
        timeline.abort();
    }
    state.redis.pubsub.native_clock.begin_case(case_id);
    state.redis.pubsub.namespace_sessions.begin_case();
    if let Some(policy) = &mut state.replay_policy {
        policy.begin_case(case_id);
    }
    if let Some(case) = state.cases.get_mut(case_id) {
        case.status = ReplayCaseStatus::Active;
    }
    let target_stop_required = state.dependency_tails.target_stop_required(case_id);
    serde_json::json!({
        "ok": true,
        "target_stop_required": target_stop_required,
        "prepared_scope": prepared_scope,
        "active_case_id": case_id,
        "case": state.cases.get(case_id).map(|case| ReplayCaseReport {
            case_id: case.id.clone(),
            case_dir: case.dir.display().to_string(),
            dependencies_path: case.dependencies_path.display().to_string(),
            status: case.status,
            source_request_started_at: state.replay_policy.as_ref()
                .and_then(|policy| policy.request_contracts.request_times(case_id).source),
            target_request_started_at: state.replay_policy.as_ref()
                .and_then(|policy| policy.request_contracts.request_times(case_id).target),
        }),
    })
}

pub(super) async fn end_case(
    request: &ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
) -> Value {
    let Some(case_id) = request.case_id.as_deref() else {
        return serde_json::json!({"ok": false, "error": "end requires case_id"});
    };
    let stopped = match target_stop::confirm(request, &state).await {
        Ok(stopped) => stopped,
        Err(error) => return serde_json::json!({"ok":false,"error":format!("{error:#}")}),
    };
    let (post_response_window, case_dir, client_aborted) = {
        let mut state = state.lock().await;
        if !state.cases.contains_key(case_id) {
            return serde_json::json!({
                "ok": false,
                "error": format!("unknown replay case {case_id}")
            });
        }
        if state.active_case_id.as_deref() != Some(case_id) {
            return serde_json::json!({
                "ok": false,
                "error": format!("replay case {case_id} is not active")
            });
        }
        state.redis.pubsub.native_clock.close_case(case_id);
        state.redis.pubsub.namespace_sessions.close_case(case_id);
        (
            state.case_dependency_post_response_window,
            state.cases[case_id].dir.clone(),
            state
                .case_cleanup
                .client_abort_at(case_id)
                .filter(|_| !stopped),
        )
    };
    let deadline = if stopped {
        dependency_tail::cleanup_deadline(&state, case_id).await
    } else {
        dependency_tail::deadline(&state, case_id).await
    };
    // A confirmed stopped Target cannot start another Case dependency. Keep
    // waiting for admitted I/O below, without an extra attribution idle window.
    let attribution_window = if stopped {
        Duration::ZERO
    } else {
        post_response_window
    };
    let cleanup = async {
        let interaction =
            interaction::drain(&state, case_id, &case_dir, attribution_window, deadline).await?;
        if !interaction && !attribution_window.is_zero() {
            tokio::time::sleep(attribution_window).await;
        }
        dependency_tail::drain(&state, case_id).await?;
        // Ordinary HTTP and failed asynchronous requests have the same actual
        // delivery barrier, including protocols absent from tail selectors.
        case_cleanup::drain_started(&state, case_id, deadline).await
    };
    let cleanup = match (client_aborted, deadline) {
        // A premature client end gets its own observation bound. The normal
        // request's deadline and unstarted business obligations are independent.
        (Some(_), _) => Ok(()),
        (None, Some(deadline)) => tokio::time::timeout_at(deadline, cleanup)
            .await
            .map_err(|_| anyhow!("dependency-tail absolute request budget expired during case cleanup; case ownership was retained"))
            .and_then(|result| result),
        (None, None) => cleanup.await,
    };
    let cleanup_failure = if let Err(error) = cleanup {
        let error = case_cleanup::failure_description(&state, &error).await;
        let mut current = state.lock().await;
        current
            .dependency_tails
            .record_cleanup_failure(case_id, &error);
        if case_cleanup::has_started(&current) {
            return serde_json::json!({"ok":false,"dirty":true,"error":error});
        }
        // An expired business budget fails this Case. With no accepted I/O
        // left, it must not strand global ownership and block later inputs.
        if let Err(failure) = case_cleanup::mark_failed(&mut current, case_id) {
            return serde_json::json!({"ok":false,"dirty":true,
                "error":format!("{error}; failed to retain Case failure: {failure:#}")});
        }
        Some(error)
    } else {
        None
    };
    let release_deadline = state
        .lock()
        .await
        .case_cleanup
        .deadline(case_id)
        .or(deadline);

    let counter_sample = {
        let release = if let Some(aborted) = client_aborted {
            case_cleanup::lock_for_abort_release(&state, case_id, aborted).await
        } else {
            case_cleanup::lock_for_release(&state, case_id, release_deadline).await
        };
        let mut state = match release {
            Ok(state) => state,
            Err(error) => {
                let error = case_cleanup::failure_description(&state, &error).await;
                return serde_json::json!({"ok":false,"dirty":true,"error":error});
            }
        };
        let sample = state
            .egress_counter_starts
            .remove(case_id)
            .zip(state.egress_counter_reader.clone());
        state.set_active_case(None);
        state.target_stop_prepared.remove(case_id);
        dependency_tail::end(&mut state, case_id);
        if state.case_cleanup.client_abort_at(case_id).is_some() {
            state.target_observations.end_abort_tail();
        }
        state.case_cleanup.end(case_id);
        if let Some(case) = state.cases.get_mut(case_id) {
            case.status = ReplayCaseStatus::Ended;
        }
        if let Some(policy) = &state.replay_policy {
            policy.request_contracts.clear_time_copies(case_id);
            policy.request_contracts.clear_identities(case_id);
        }
        deferred::release_consumed_payloads(&mut state);
        sample
    };
    if let Some((before, reader)) = counter_sample {
        let after = reader.sample().await;
        state.lock().await.egress_rejections.insert(
            case_id.to_string(),
            egress_counter::difference(case_id, before, after),
        );
    }
    let state = state.lock().await;
    let dirty = state.case_is_dirty(case_id);
    if let Some(error) = cleanup_failure {
        return serde_json::json!({"ok":false,"dirty":true,"case_finished":true,"error":error});
    }
    if request.fail_on_dirty && dirty {
        serde_json::json!({
            "ok": false,
            "dirty": true,
            "error": format!("replay case {case_id} has dirty dependency evidence"),
        })
    } else {
        serde_json::json!({
            "ok": true,
            "dirty": dirty,
        })
    }
}

fn control_peer_disconnected(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

async fn write_control_response(
    stream: &mut UnixStream,
    command: &str,
    response: Value,
) -> Result<()> {
    let mut payload =
        serde_json::to_vec(&response).context("failed to serialize replay control response")?;
    payload.push(b'\n');
    match stream.write_all(&payload).await {
        Err(error) if control_peer_disconnected(&error) => {
            tracing::debug!(command, %error, "replay control client disconnected before reading its response");
            Ok(())
        }
        result => result.context("failed to write replay control response"),
    }
}

pub(super) async fn write_session_snapshot(
    state: Arc<Mutex<ReplayState>>,
    session_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
    report_path: Option<PathBuf>,
    ready: bool,
) -> Result<()> {
    let Some(session_path) = session_path else {
        return Ok(());
    };
    let snapshot = {
        let state = state.lock().await;
        session_discovery_snapshot(
            &state,
            control_socket_path.as_ref(),
            report_path.as_ref(),
            ready,
        )
    };
    if let Some(parent) = session_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay session dir {}", parent.display()))?;
    }
    let mut payload =
        serde_json::to_vec_pretty(&snapshot).context("failed to serialize replay session")?;
    payload.push(b'\n');
    tokio::fs::write(&session_path, payload)
        .await
        .with_context(|| format!("failed to write replay session {}", session_path.display()))
}

fn session_discovery_snapshot(
    state: &ReplayState,
    control_socket_path: Option<&PathBuf>,
    report_path: Option<&PathBuf>,
    ready: bool,
) -> Value {
    serde_json::json!({
        "version": 3,
        "session_id": state.session_id.to_string(),
        "control_socket": control_socket_path.map(|path| path.display().to_string()),
        "report_path": report_path.map(|path| path.display().to_string()),
        "pid": std::process::id(),
        "ready": ready,
    })
}

pub(super) fn session_snapshot(
    state: &ReplayState,
    control_socket_path: Option<&PathBuf>,
    report_path: Option<&PathBuf>,
    ready: bool,
) -> Value {
    serde_json::json!({
        "version": 2,
        "session_id": state.session_id.to_string(),
        "started_at": state.started_at,
        "finalized_at": state.finalized_at,
        "finalized": state.finalized_at.is_some(),
        "root": state.root_dir.display().to_string(),
        "mode": state.mode,
        "control_socket": control_socket_path.map(|path| path.display().to_string()),
        "report_path": report_path.map(|path| path.display().to_string()),
        "pid": std::process::id(),
        "ready": ready,
        "dns_listen": state.dns_listen.to_string(),
        "tcp_listen": state.tcp_listen.to_string(),
        "ca_cert_path": state.ca_cert_path.display().to_string(),
        "replay_policy": state.replay_policy.as_ref().map(ReplayPolicyRuntime::report),
        "active_case_id": state.active_case_id.clone(),
        "cases": state.case_reports(),
        "selected_case_ids": state.cases.keys().cloned().collect::<Vec<_>>(),
        "waiting": state.active_case_id.as_deref().and_then(|case| state.dependency_tails.waiting(case)),
    })
}

pub(super) fn report_is_dirty(report: &ReplayReport) -> bool {
    report.is_dirty()
}

pub(super) fn report_is_complete(report: &ReplayReport) -> bool {
    report.is_complete()
}

impl ReplayState {
    fn case_is_dirty(&self, case_id: &str) -> bool {
        if self.dependency_tails.failure(case_id).is_some() {
            return true;
        }
        if self.connect_failures.case_is_dirty(case_id) {
            return true;
        }
        let dirty = self.unrecorded_case_ids.contains(case_id)
            || self.mysql.case_is_dirty(case_id)
            || self.http_case_is_dirty(case_id)
            || self.redis.case_is_dirty(case_id)
            || self.memcached.case_is_dirty(case_id)
            || self.kafka.case_is_dirty(case_id)
            || self.motan.case_is_dirty(case_id);
        #[cfg(test)]
        {
            debug_assert_eq!(
                self.redis.case_is_dirty(case_id),
                self.redis.snapshot().case_is_dirty(case_id)
            );
            debug_assert_eq!(
                self.memcached.case_is_dirty(case_id),
                self.memcached.snapshot().case_is_dirty(case_id)
            );
            debug_assert_eq!(
                self.kafka.case_is_dirty(case_id),
                self.kafka.snapshot().case_is_dirty(case_id)
            );
            debug_assert_eq!(
                self.motan.case_is_dirty(case_id),
                self.motan.snapshot().case_is_dirty(case_id)
            );
        }
        dirty
    }
}

#[cfg(test)]
mod tests;
