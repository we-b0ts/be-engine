use std::time::{Duration, Instant};

use super::*;

#[allow(dead_code)]
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) mod case_cleanup;
mod case_execution;
pub(crate) mod dependency_tail;
mod derived_input;
mod finalization;
use finalization::FinalizationCheck;
pub use finalization::FinalizationScope;
mod extensions;
pub(crate) mod input_timing;
mod interaction;
mod interruption;
mod native_event;
pub(crate) mod primary_close;
mod server;
mod target_stop;
pub(crate) use server::run_control_socket;
pub use traffic_engine_replay::replay::control::MAX_CONTROL_BYTES;
#[allow(dead_code)]
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[allow(dead_code)]
const READY_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
pub(crate) struct ReplayControlRequest {
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) case_id: Option<String>,
    #[serde(default)]
    pub(crate) fail_on_dirty: bool,
    #[serde(default)]
    pub(crate) fail_on_incomplete: bool,
    #[serde(flatten, deserialize_with = "traffic_contract::codec::unique_map")]
    pub(crate) parameters: BTreeMap<String, traffic_value::Value>,
    #[serde(default)]
    pub(crate) derived_input: Option<derived_input::Registration>,
    #[serde(default)]
    pub(crate) native_event: Option<native_event::Observation>,
    #[serde(default)]
    pub(crate) input_timing: Option<input_timing::Query>,
    #[serde(default)]
    pub(crate) socketio_timing: Option<crate::interaction::replay::timing::SocketIoTiming>,
}

pub(crate) async fn handle_control_request<P: ReplayProtocolSet>(
    request: ReplayControlRequest,
    state: Arc<Mutex<RuntimeState<P>>>,
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
                    .map(|policy| policy.contracts().request_begin(case))
                    .transpose()
                {
                    Ok(_) => {
                        state.close_startup_phase(case);
                        let epoch = state
                            .replay_policy
                            .as_ref()
                            .and_then(|policy| policy.contracts().request_times(case).target)
                            .unwrap_or_else(Utc::now);
                        match state.protocols.native_events().request_begin(case, epoch) {
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
        "case_close_tail" | "case_client_aborted" => {
            let mut state = state.lock().await;
            let result = request
                .case_id
                .as_deref()
                .context("close tail observation requires case_id")
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
        "derived_input" => derived_input::accept(&request, &state).await,
        "native_event_begin" | "native_event" | "native_connected" | "native_input_ack" => {
            native_event::accept(&request, &state).await
        }
        "input_timing_begin"
        | "input_timing"
        | "input_timing_tail"
        | "input_timing_native_prefix" => input_timing::accept(&request, &state).await,
        "http_input_timing_begin" | "http_input_timing_wait" | "http_input_timing_closed" => {
            primary_close::accept(&request, &state).await
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
        _ => extensions::accept(&request, &state).await,
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
            let providers = state.lock().await.providers.clone();
            write_final_report_value(path, report, providers.report_codecs()).await?;
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

async fn finalize_replay<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: Arc<Mutex<RuntimeState<P>>>,
) -> (Value, Option<Value>) {
    if let Err(error) = policy::await_durable(&state).await {
        tracing::warn!(error=%error,"finalizing incomplete hypothesis evidence");
    }
    let mut state = state.lock().await;
    if state.has_protocol_io(InFlightScope::All) {
        return (
            serde_json::json!({"ok":false,"complete":false,"error":"cannot finalize Replay while dependency delivery or termination evidence is still in flight"}),
            None,
        );
    }
    let mut report = state.snapshot_report();
    let complete = report_is_complete(&report);
    let dirty = FinalizationScope::from_command(&request.command)
        .is_dirty(&report, state.providers.report_codecs());
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
    state.native.core.lifecycle.notify_waiters();
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

pub(crate) async fn begin_case<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: Arc<Mutex<RuntimeState<P>>>,
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
    if let Err(error) = input_timing::prepare_source(&state, case_id).await {
        return serde_json::json!({"ok": false, "error": format!("input timing preparation failed: {error:#}")});
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
            "indexed_native_counts": plan.native.protocols.iter()
                .map(|(protocol, inventory)| (protocol.as_str(), inventory.members.len()))
                .collect::<BTreeMap<_, _>>(),
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
    if let Some(timeline) = state.primary_close_timing.take() {
        timeline.abort();
    }
    state.protocols.begin_case(case_id);
    if let Some(policy) = &mut state.replay_policy {
        policy.begin_case(case_id);
    } else {
        state.native.contracts.begin_case(case_id);
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
                .and_then(|policy| policy.contracts().request_times(case_id).source),
            target_request_started_at: state.replay_policy.as_ref()
                .and_then(|policy| policy.contracts().request_times(case_id).target),
        }),
    })
}

pub(crate) async fn end_case<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: Arc<Mutex<RuntimeState<P>>>,
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
        state.protocols.close_case(case_id);
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
        // A close with pending business gets its own observation bound. The normal
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
        state.native.clear_storage_deliveries(case_id);
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
            policy.contracts().clear_case_values(case_id);
        } else {
            state.native.contracts.clear_case_values(case_id);
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

pub(crate) async fn write_session_snapshot<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
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

fn session_discovery_snapshot<P: ReplayProtocolSet>(
    state: &RuntimeState<P>,
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

pub(crate) fn session_snapshot<P: ReplayProtocolSet>(
    state: &RuntimeState<P>,
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
        "replay_policy": state.replay_policy.as_ref().map(ReplayPolicy::report),
        "active_case_id": state.active_case_id.clone(),
        "cases": state.case_reports(),
        "selected_case_ids": state.cases.keys().cloned().collect::<Vec<_>>(),
        "waiting": state.active_case_id.as_deref().and_then(|case| state.dependency_tails.waiting(case)),
    })
}

pub(crate) fn report_is_dirty<S: traffic_replay::report::SessionSnapshot>(
    report: &ReplayReport<S>,
) -> bool {
    report.is_dirty()
}

pub(crate) fn report_is_complete<S: traffic_replay::report::SessionSnapshot>(
    report: &ReplayReport<S>,
) -> bool {
    report.is_complete()
}

impl<P: ReplayProtocolSet> RuntimeState<P> {
    fn case_is_dirty(&self, case: &str) -> bool {
        self.dependency_tails.failure(case).is_some()
            || self.connect_failures.case_is_dirty(case)
            || self.unrecorded_case_ids.contains(case)
            || self.native.case_is_dirty(case)
            || self.protocols.case_is_dirty(case)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub use traffic_engine_replay::replay::control::send_control_request;
