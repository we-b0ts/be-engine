use std::time::{Duration, Instant};

use super::*;

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);
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

pub(super) async fn run_control_socket(
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    session_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
) -> Result<()> {
    let Some(control_socket_path) = control_socket_path else {
        return pending::<Result<()>>().await;
    };
    if let Some(parent) = control_socket_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create replay control dir {}", parent.display()))?;
    }
    if tokio::fs::try_exists(&control_socket_path)
        .await
        .unwrap_or(false)
    {
        tokio::fs::remove_file(&control_socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove stale replay control socket {}",
                    control_socket_path.display()
                )
            })?;
    }
    let listener = UnixListener::bind(&control_socket_path).with_context(|| {
        format!(
            "failed to bind replay control socket {}",
            control_socket_path.display()
        )
    })?;
    write_session_snapshot(
        state.clone(),
        session_path.clone(),
        Some(control_socket_path.clone()),
        report_path.clone(),
        true,
    )
    .await?;
    info!(
        control_socket = %control_socket_path.display(),
        "MySQL dependency replay control listening"
    );

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept replay control client")?;
        if handle_control_stream(
            stream,
            state.clone(),
            report_path.clone(),
            Some(control_socket_path.clone()),
        )
        .await?
        {
            break;
        }
    }
    write_session_snapshot(
        state,
        session_path,
        Some(control_socket_path.clone()),
        report_path,
        false,
    )
    .await?;
    let _ = tokio::fs::remove_file(control_socket_path).await;
    Ok(())
}

pub(super) fn process_exists(pid: u64) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(super) async fn handle_control_stream(
    stream: UnixStream,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
) -> Result<bool> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("failed to read replay control request")?;
    let mut stream = reader.into_inner();
    let request: ReplayControlRequest = match serde_json::from_str(line.trim()) {
        Ok(request) => request,
        Err(err) => {
            write_control_response(
                &mut stream,
                serde_json::json!({
                    "ok": false,
                    "error": format!("invalid replay control request: {err}")
                }),
            )
            .await?;
            return Ok(false);
        }
    };

    let (response, should_stop) = handle_control_request(
        request,
        state.clone(),
        report_path.clone(),
        control_socket_path.clone(),
    )
    .await;
    write_control_response(&mut stream, response).await?;
    Ok(should_stop)
}

pub(super) async fn handle_control_request(
    request: ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
) -> (Value, bool) {
    let command = request.command.as_str();
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
        "begin" => begin_case(&request, state.clone()).await,
        "end" => end_case(&request, state.clone()).await,
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
                    "error": "replay report has unmatched, unused, or unsupported exchanges",
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
        "finalize" => finalize_replay(&request, state.clone()).await,
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
        || (command == "finalize" && response.get("ok").and_then(Value::as_bool).unwrap_or(false));
    if command == "finalize" && should_stop && report_path.is_none() {
        state.lock().await.finalized_at = None;
        return (
            serde_json::json!({
                "ok": false,
                "error": "cannot finalize replay without a configured report path",
            }),
            false,
        );
    }
    if command == "finalize"
        && should_stop
        && let Err(error) = write_final_report_value(
            report_path.expect("finalize report path checked"),
            &response["report"],
        )
        .await
    {
        state.lock().await.finalized_at = None;
        return (
            serde_json::json!({
                "ok": false,
                "error": format!("failed to persist replay report: {error:#}"),
            }),
            false,
        );
    }
    (response, should_stop)
}

async fn finalize_replay(request: &ReplayControlRequest, state: Arc<Mutex<ReplayState>>) -> Value {
    let mut state = state.lock().await;
    let mut report = state.snapshot_report();
    let complete = report_is_complete(&report);
    let dirty = report_is_dirty(&report);
    if request.fail_on_incomplete && !complete {
        return serde_json::json!({
            "ok": false,
            "complete": false,
            "dirty": dirty,
            "error": "cannot finalize replay with pending or active cases",
        });
    }
    if request.fail_on_dirty && dirty {
        return serde_json::json!({
            "ok": false,
            "complete": complete,
            "dirty": true,
            "error": "cannot finalize replay with unmatched, unused, or unsupported exchanges",
        });
    }
    let finalized_at = Utc::now();
    state.finalized_at = Some(finalized_at);
    report.finalized_at = Some(finalized_at);
    report.finalized = true;
    serde_json::json!({
        "ok": true,
        "complete": complete,
        "dirty": dirty,
        "finalized": true,
        "report": report,
    })
}

pub(super) async fn begin_case(
    request: &ReplayControlRequest,
    state: Arc<Mutex<ReplayState>>,
) -> Value {
    let Some(case_id) = request.case_id.as_deref() else {
        return serde_json::json!({"ok": false, "error": "begin requires case_id"});
    };
    let mut state = state.lock().await;
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
    if !state.egress_counter_starts.contains_key(case_id)
        && let Some(reader) = &state.egress_counter_reader
    {
        let sample = reader.sample().await;
        state
            .egress_counter_starts
            .insert(case_id.to_string(), sample);
    }
    state.active_case_id = Some(case_id.to_string());
    if let Some(policy) = &mut state.replay_policy {
        policy.begin_case(case_id);
    }
    if let Some(case) = state.cases.get_mut(case_id) {
        case.status = ReplayCaseStatus::Active;
    }
    serde_json::json!({
        "ok": true,
        "active_case_id": case_id,
        "case": state.cases.get(case_id).map(|case| ReplayCaseReport {
            case_id: case.id.clone(),
            case_dir: case.dir.display().to_string(),
            dependencies_path: case.dependencies_path.display().to_string(),
            status: case.status,
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
    let post_response_window = {
        let state = state.lock().await;
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
        state.case_dependency_post_response_window
    };
    if !post_response_window.is_zero() {
        tokio::time::sleep(post_response_window).await;
    }

    let mut state = state.lock().await;
    if state.active_case_id.as_deref() != Some(case_id) {
        return serde_json::json!({
            "ok": false,
            "error": format!("replay case {case_id} is no longer active")
        });
    }
    if let Some(before) = state.egress_counter_starts.remove(case_id)
        && let Some(reader) = &state.egress_counter_reader
    {
        let after = reader.sample().await;
        state.egress_rejections.insert(
            case_id.to_string(),
            egress_counter::difference(case_id, before, after),
        );
    }
    state.active_case_id = None;
    if let Some(case) = state.cases.get_mut(case_id) {
        case.status = ReplayCaseStatus::Ended;
    }
    let dirty = state.case_is_dirty(case_id);
    if request.fail_on_dirty && dirty {
        serde_json::json!({
            "ok": false,
            "dirty": true,
            "error": format!("replay case {case_id} has unmatched, unused, or unsupported exchanges"),
        })
    } else {
        serde_json::json!({
            "ok": true,
            "dirty": dirty,
        })
    }
}

pub(super) async fn write_control_response(stream: &mut UnixStream, response: Value) -> Result<()> {
    let mut payload =
        serde_json::to_vec(&response).context("failed to serialize replay control response")?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .context("failed to write replay control response")
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
        self.unrecorded_targets
            .iter()
            .any(|target| target.case_id.as_deref() == Some(case_id))
            || self
                .mysql
                .events
                .unmatched_queries
                .iter()
                .any(|query| query.case_id.as_deref() == Some(case_id))
            || self
                .mysql
                .events
                .unsupported_commands
                .iter()
                .any(|query| query.case_id.as_deref() == Some(case_id))
            || self.mysql.exchanges.iter().any(|exchange| {
                let optional = exchange.optional_session.filter(|kind| {
                    exchange.status.is_available()
                        || *kind == OptionalSessionExchange::Rollback
                            && exchange.status == ReplayExchangeStatus::Responding
                });
                exchange.source == ReplaySource::Case
                    && exchange.case_id.as_deref() == Some(case_id)
                    && !exchange.status.is_consumed()
                    && optional.is_none()
            })
            || self.http_case_is_dirty(case_id)
            || self.redis.snapshot().case_is_dirty(case_id)
            || self.memcached.snapshot().case_is_dirty(case_id)
            || self.kafka.snapshot().case_is_dirty(case_id)
            || self.motan.snapshot().case_is_dirty(case_id)
    }
}

#[cfg(test)]
mod tests;
