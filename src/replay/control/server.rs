//! Bounded control transport with serialized mutations and concurrent observations.
use super::*;
const MAX_CLIENTS: usize = 32;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

pub(in crate::replay) async fn run_control_socket(
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

    // Mutations retain one owner; read-only observations must remain available
    // while end waits for an asynchronous dependency tail.
    let mutation = Arc::new(Mutex::new(()));
    let mut clients = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            completed = clients.join_next(), if !clients.is_empty() => {
                match completed {
                    Some(Ok(Ok(true))) => break,
                    Some(Ok(Ok(false))) => {},
                    Some(Ok(Err(error))) => warn!(%error, "replay control client failed"),
                    Some(Err(error)) => warn!(%error, "replay control client task failed"),
                    None => {},
                }
            }
            accepted = listener.accept(), if clients.len() < MAX_CLIENTS => {
                let (stream, _) = accepted.context("failed to accept replay control client")?;
                clients.spawn(serve(stream, state.clone(), report_path.clone(),
                    Some(control_socket_path.clone()), mutation.clone()));
            }
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
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

async fn serve(
    stream: UnixStream,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
    mutation: Arc<Mutex<()>>,
) -> Result<bool> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    use tokio::io::AsyncReadExt;
    let read = tokio::time::timeout(FRAME_TIMEOUT, async {
        (&mut reader)
            .take(identity::MAX_CONTROL_BYTES as u64 + 1)
            .read_line(&mut line)
            .await
    })
    .await;
    let Ok(read) = read else {
        return Ok(false);
    };
    match read {
        Ok(0) => return Ok(false),
        Err(error) if control_peer_disconnected(&error) => return Ok(false),
        read => {
            read.context("failed to read replay control request")?;
        }
    }
    let mut stream = reader.into_inner();
    if line.len() > identity::MAX_CONTROL_BYTES {
        write_control_response(
            &mut stream,
            "oversized_request",
            serde_json::json!({
                "ok": false, "error": "replay control request exceeds the supported bound"
            }),
        )
        .await?;
        return Ok(false);
    }
    let request: ReplayControlRequest = match serde_json::from_str(line.trim()) {
        Ok(request) => request,
        Err(err) => {
            write_control_response(
                &mut stream,
                "invalid_request",
                serde_json::json!({
                    "ok": false,
                    "error": format!("invalid replay control request: {err}")
                }),
            )
            .await?;
            return Ok(false);
        }
    };

    let command = request.command.clone();
    let queued_at = Instant::now();
    let _mutation = if matches!(
        command.as_str(),
        "status" | "wait_ready" | "cases" | "case_execution_status" | "response_time_copies"
    ) {
        None
    } else {
        Some(mutation.lock().await)
    };
    let started = Instant::now();
    let sequence = request.input_timing.as_ref().map(|query| query.sequence);
    let (response, should_stop) = handle_control_request(
        request,
        state.clone(),
        report_path.clone(),
        control_socket_path.clone(),
    )
    .await;
    if command == "input_timing" && queued_at.elapsed() >= Duration::from_millis(250) {
        warn!(
            ?sequence,
            control_queue_ms = started.duration_since(queued_at).as_millis(),
            handler_ms = started.elapsed().as_millis(),
            "slow Socket.IO input control feedback"
        );
    }
    // Commit the command independently of whether its observer still reads.
    let _ = tokio::time::timeout(
        FRAME_TIMEOUT,
        write_control_response(&mut stream, &command, response),
    )
    .await;
    Ok(should_stop)
}

#[cfg(test)]
pub(in crate::replay) async fn handle_control_stream(
    stream: UnixStream,
    state: Arc<Mutex<ReplayState>>,
    report_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
) -> Result<bool> {
    serve(
        stream,
        state,
        report_path,
        control_socket_path,
        Arc::new(Mutex::new(())),
    )
    .await
}
