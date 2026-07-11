#[derive(Debug, Deserialize)]
pub(super) struct ReplayControlRequest {
    pub(super) command: String,
    #[serde(default)]
    pub(super) case_id: Option<String>,
    #[serde(default)]
    pub(super) fail_on_dirty: bool,
}

pub(crate) async fn send_control_request(config: MysqlReplayControlConfig) -> Result<Value> {
    if config.command == "wait_ready" {
        let mut last_error = None;
        for _ in 0..200 {
            match send_control_request_once(config.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    last_error = Some(err);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if let Some(err) = last_error {
            return Err(err).context("replay session did not become ready");
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
        let message = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("replay control command failed");
        Err(anyhow!("{message}: {}", serde_json::to_string(&response)?))
    }
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
            session_path.clone(),
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
    session_path: Option<PathBuf>,
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
    write_session_snapshot(
        state,
        session_path,
        control_socket_path,
        report_path.clone(),
        !should_stop,
    )
    .await?;
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
            if request.fail_on_dirty && dirty {
                serde_json::json!({
                    "ok": false,
                    "dirty": true,
                    "error": "replay report has unmatched, unused, or unsupported exchanges",
                    "report": report,
                })
            } else {
                serde_json::json!({
                    "ok": true,
                    "dirty": dirty,
                    "report": report,
                })
            }
        }
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
    let _ = write_report_snapshot(state, report_path).await;
    (response, command == "stop")
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
    state.active_case_id = Some(case_id.to_string());
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
    state.active_case_id = None;
    if let Some(case) = state.cases.get_mut(case_id) {
        case.status = ReplayCaseStatus::Ended;
    }
    let report = state.snapshot_report();
    let dirty = case_is_dirty(&report, case_id);
    if request.fail_on_dirty && dirty {
        serde_json::json!({
            "ok": false,
            "dirty": true,
            "error": format!("replay case {case_id} has unmatched, unused, or unsupported exchanges"),
            "report": report,
        })
    } else {
        serde_json::json!({
            "ok": true,
            "dirty": dirty,
            "report": report,
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
        session_snapshot(
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

pub(super) fn session_snapshot(
    state: &ReplayState,
    control_socket_path: Option<&PathBuf>,
    report_path: Option<&PathBuf>,
    ready: bool,
) -> Value {
    serde_json::json!({
        "version": 1,
        "session_id": state.session_id.to_string(),
        "root": state.root_dir.display().to_string(),
        "mode": state.mode,
        "control_socket": control_socket_path.map(|path| path.display().to_string()),
        "report_path": report_path.map(|path| path.display().to_string()),
        "pid": std::process::id(),
        "ready": ready,
        "dns_listen": state.dns_listen.to_string(),
        "tcp_listen": state.tcp_listen.to_string(),
        "ca_cert_path": state.ca_cert_path.display().to_string(),
        "active_case_id": state.active_case_id.clone(),
        "cases": state.case_reports(),
    })
}

pub(super) fn report_is_dirty(report: &ReplayReport) -> bool {
    !report.unmatched_queries.is_empty()
        || !report.unsupported_commands.is_empty()
        || !report.unused_case_exchanges.is_empty()
        || !report.unused_bootstrap_exchanges.is_empty()
        || !report.unmatched_http_requests.is_empty()
        || !report.unsupported_http_exchanges.is_empty()
        || !report.unused_case_http_exchanges.is_empty()
        || !report.unused_bootstrap_http_exchanges.is_empty()
        || cache_report_is_dirty(&report.protocols.redis)
        || cache_report_is_dirty(&report.protocols.memcached)
}

pub(super) fn case_is_dirty(report: &ReplayReport, case_id: &str) -> bool {
    report
        .unmatched_queries
        .iter()
        .any(|query| query.case_id.as_deref() == Some(case_id))
        || report
            .unsupported_commands
            .iter()
            .any(|query| query.case_id.as_deref() == Some(case_id))
        || report
            .unused_case_exchanges
            .iter()
            .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
        || report
            .unmatched_http_requests
            .iter()
            .any(|request| request.case_id.as_deref() == Some(case_id))
        || report
            .unsupported_http_exchanges
            .iter()
            .any(|request| request.case_id.as_deref() == Some(case_id))
        || report
            .unused_case_http_exchanges
            .iter()
            .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
        || cache_case_is_dirty(&report.protocols.redis, case_id)
        || cache_case_is_dirty(&report.protocols.memcached, case_id)
}

pub(super) fn cache_report_is_dirty(report: &cache::CacheProtocolReport) -> bool {
    !report.unmatched.is_empty()
        || !report.unsupported.is_empty()
        || !report.unsafe_events.is_empty()
        || !report.unused_case.is_empty()
        || !report.unused_bootstrap.is_empty()
}

pub(super) fn cache_case_is_dirty(report: &cache::CacheProtocolReport, case_id: &str) -> bool {
    report
        .unmatched
        .iter()
        .any(|request| request.case_id.as_deref() == Some(case_id))
        || report
            .unsupported
            .iter()
            .any(|request| request.case_id.as_deref() == Some(case_id))
        || report
            .unsafe_events
            .iter()
            .any(|request| request.case_id.as_deref() == Some(case_id))
        || report
            .unused_case
            .iter()
            .any(|exchange| exchange.case_id.as_deref() == Some(case_id))
}
use super::*;
