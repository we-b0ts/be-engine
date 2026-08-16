use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::AppConfig;

const CONTROL_REQUEST_LIMIT_BYTES: u64 = 4096;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct RecordingWaitConfig {
    pub control_socket_path: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordingInputCompletion {
    pub(crate) delivered: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordingListener {
    HttpProxy,
    DnsMock,
    TcpGateway,
    UdpGateway,
    HttpGateway,
    MotanGateway,
    Mysql,
}

impl RecordingListener {
    fn as_str(self) -> &'static str {
        match self {
            Self::HttpProxy => "http_proxy",
            Self::DnsMock => "dns_mock",
            Self::TcpGateway => "tcp_gateway",
            Self::UdpGateway => "udp_gateway",
            Self::HttpGateway => "http_gateway",
            Self::MotanGateway => "motan_gateway",
            Self::Mysql => "mysql",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecordingReadiness {
    pub phase: String,
    pub ready: bool,
    pub listeners_bound: bool,
    pub source_ready: bool,
    pub listeners_ready: Vec<String>,
    pub listeners_pending: Vec<String>,
    #[serde(default)]
    pub upstreams_ready: Vec<String>,
    #[serde(default)]
    pub upstreams_pending: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug)]
struct RecordingLifecycleState {
    expected: BTreeSet<RecordingListener>,
    listening: BTreeSet<RecordingListener>,
    expected_upstreams: BTreeSet<RecordingListener>,
    ready_upstreams: BTreeSet<RecordingListener>,
    source_settling: bool,
    source_ready: bool,
    stopping: bool,
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RecordingLifecycle {
    inner: Arc<Mutex<RecordingLifecycleState>>,
}

impl RecordingLifecycle {
    pub(crate) fn from_config(config: &AppConfig) -> Self {
        let mut expected = BTreeSet::new();
        if config.http.enabled {
            expected.insert(RecordingListener::HttpProxy);
        }
        if config.dns_mock.enabled {
            expected.insert(RecordingListener::DnsMock);
        }
        if config.tcp_gateway.enabled {
            expected.insert(RecordingListener::TcpGateway);
        }
        if config.udp_gateway.enabled {
            expected.insert(RecordingListener::UdpGateway);
        }
        if config.http_gateway.enabled {
            expected.insert(RecordingListener::HttpGateway);
        }
        if config.motan_gateway.enabled {
            expected.insert(RecordingListener::MotanGateway);
        }
        if config.mysql.enabled {
            expected.insert(RecordingListener::Mysql);
        }
        let expected_upstreams = expected_upstreams(
            config.http_gateway.enabled && config.http_gateway.ready.enabled,
            config.motan_gateway.enabled,
        );
        let source_ready = expected_upstreams.is_empty();
        Self {
            inner: Arc::new(Mutex::new(RecordingLifecycleState {
                expected,
                listening: BTreeSet::new(),
                expected_upstreams,
                ready_upstreams: BTreeSet::new(),
                source_settling: false,
                source_ready,
                stopping: false,
                error: None,
            })),
        }
    }

    pub(crate) fn for_comparison_gateway(
        http_enabled: bool,
        http_readiness_enabled: bool,
        motan_enabled: bool,
    ) -> Self {
        let mut expected = BTreeSet::new();
        if http_enabled {
            expected.insert(RecordingListener::HttpGateway);
        }
        if motan_enabled {
            expected.insert(RecordingListener::MotanGateway);
        }
        let expected_upstreams =
            expected_upstreams(http_enabled && http_readiness_enabled, motan_enabled);
        let source_ready = expected_upstreams.is_empty();
        Self {
            inner: Arc::new(Mutex::new(RecordingLifecycleState {
                expected,
                listening: BTreeSet::new(),
                expected_upstreams,
                ready_upstreams: BTreeSet::new(),
                source_settling: false,
                source_ready,
                stopping: false,
                error: None,
            })),
        }
    }

    pub(crate) fn mark_listener_ready(&self, listener: RecordingListener) {
        self.lock().listening.insert(listener);
    }

    pub(crate) fn mark_upstream_ready(&self, listener: RecordingListener) -> bool {
        let mut state = self.lock();
        if !state.expected_upstreams.contains(&listener) || !state.ready_upstreams.insert(listener)
        {
            return false;
        }
        let all_ready = state.ready_upstreams == state.expected_upstreams;
        if all_ready {
            state.source_settling = true;
        }
        all_ready
    }

    pub(crate) fn mark_source_ready(&self) {
        let mut state = self.lock();
        state.source_settling = false;
        state.source_ready = true;
    }

    pub(crate) fn mark_stopping(&self) {
        self.lock().stopping = true;
    }

    pub(crate) fn mark_failed(&self, error: impl std::fmt::Display) {
        let mut state = self.lock();
        if state.error.is_none() {
            state.error = Some(bound_error(error.to_string()));
        }
    }

    pub(crate) fn snapshot(&self) -> RecordingReadiness {
        let state = self.lock();
        let listeners_ready = state
            .listening
            .iter()
            .copied()
            .map(RecordingListener::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        let listeners_pending = state
            .expected
            .difference(&state.listening)
            .copied()
            .map(RecordingListener::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        let listeners_bound = listeners_pending.is_empty();
        let upstreams_ready = state
            .ready_upstreams
            .iter()
            .copied()
            .map(RecordingListener::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        let upstreams_pending = state
            .expected_upstreams
            .difference(&state.ready_upstreams)
            .copied()
            .map(RecordingListener::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        let ready =
            state.error.is_none() && !state.stopping && state.source_ready && listeners_bound;
        let phase = if state.error.is_some() {
            "failed"
        } else if state.stopping {
            "stopping"
        } else if ready {
            "ready"
        } else if !listeners_bound {
            "starting"
        } else if state.source_settling {
            "settling"
        } else {
            "waiting_for_source"
        };
        RecordingReadiness {
            phase: phase.to_string(),
            ready,
            listeners_bound,
            source_ready: state.source_ready,
            listeners_ready,
            listeners_pending,
            upstreams_ready,
            upstreams_pending,
            error: state.error.clone(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RecordingLifecycleState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn expected_upstreams(
    http_readiness_enabled: bool,
    motan_enabled: bool,
) -> BTreeSet<RecordingListener> {
    let mut expected = BTreeSet::new();
    if http_readiness_enabled {
        expected.insert(RecordingListener::HttpGateway);
    }
    if motan_enabled {
        expected.insert(RecordingListener::MotanGateway);
    }
    expected
}

pub(crate) struct RecordingControlServer {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl RecordingControlServer {
    pub(crate) async fn start(lifecycle: RecordingLifecycle, path: PathBuf) -> Result<Self> {
        Self::start_inner(lifecycle, path, None).await
    }

    pub(crate) async fn start_for_comparison(
        lifecycle: RecordingLifecycle,
        path: PathBuf,
    ) -> Result<(Self, watch::Receiver<Option<RecordingInputCompletion>>)> {
        let (input_completion, receiver) = watch::channel(None);
        let server = Self::start_inner(lifecycle, path, Some(input_completion)).await?;
        Ok((server, receiver))
    }

    async fn start_inner(
        lifecycle: RecordingLifecycle,
        path: PathBuf,
        input_completion: Option<watch::Sender<Option<RecordingInputCompletion>>>,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "failed to create recording control directory {}",
                    parent.display()
                )
            })?;
        }
        remove_stale_socket(&path).await?;
        let listener = UnixListener::bind(&path).with_context(|| {
            format!("failed to bind recording control socket {}", path.display())
        })?;
        if let Err(error) =
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
        {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(error).with_context(|| {
                format!(
                    "failed to protect recording control socket {}",
                    path.display()
                )
            });
        }
        info!(
            control_socket = %path.display(),
            "recording control listening"
        );
        let task = tokio::spawn(run_server(listener, lifecycle, input_completion));
        Ok(Self { path, task })
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        self.task.abort();
        match self.task.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error).context("recording control task failed"),
        }
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to remove recording control socket {}",
                    self.path.display()
                )
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RecordingControlRequest {
    command: String,
    #[serde(default)]
    delivered: Option<usize>,
}

async fn run_server(
    listener: UnixListener,
    lifecycle: RecordingLifecycle,
    input_completion: Option<watch::Sender<Option<RecordingInputCompletion>>>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                warn!(error = %error, "recording control accept failed");
                return;
            }
        };
        match tokio::time::timeout(
            CONTROL_IO_TIMEOUT,
            handle_stream(stream, &lifecycle, input_completion.as_ref()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(error = %format!("{error:#}"), "recording control request failed");
            }
            Err(_) => {
                warn!("recording control request timed out");
            }
        }
    }
}

async fn handle_stream(
    stream: UnixStream,
    lifecycle: &RecordingLifecycle,
    input_completion: Option<&watch::Sender<Option<RecordingInputCompletion>>>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut request_bytes = Vec::new();
    read_half
        .take(CONTROL_REQUEST_LIMIT_BYTES + 1)
        .read_to_end(&mut request_bytes)
        .await
        .context("failed to read recording control request")?;
    ensure!(
        request_bytes.len() <= CONTROL_REQUEST_LIMIT_BYTES as usize,
        "recording control request exceeds {CONTROL_REQUEST_LIMIT_BYTES} bytes"
    );
    let request: RecordingControlRequest = serde_json::from_slice(&request_bytes)
        .context("failed to parse recording control request")?;
    let response = match request.command.as_str() {
        "status" => status_response(lifecycle.snapshot()),
        "input-complete" => input_complete_response(input_completion, request.delivered),
        other => serde_json::json!({
            "ok": false,
            "error": format!("unknown recording control command {other}"),
        }),
    };
    let mut payload =
        serde_json::to_vec(&response).context("failed to serialize recording control response")?;
    payload.push(b'\n');
    write_half
        .write_all(&payload)
        .await
        .context("failed to write recording control response")?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct RecordingControlResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<RecordingReadiness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn status_response(status: RecordingReadiness) -> Value {
    serde_json::json!({
        "ok": true,
        "status": status,
    })
}

fn input_complete_response(
    input_completion: Option<&watch::Sender<Option<RecordingInputCompletion>>>,
    delivered: Option<usize>,
) -> Value {
    let Some(input_completion) = input_completion else {
        return serde_json::json!({
            "ok": false,
            "error": "recording control does not accept finite input completion",
        });
    };
    let Some(delivered) = delivered.filter(|value| *value > 0) else {
        return serde_json::json!({
            "ok": false,
            "error": "recording input completion requires a positive delivered count",
        });
    };
    if input_completion
        .send(Some(RecordingInputCompletion { delivered }))
        .is_err()
    {
        return serde_json::json!({
            "ok": false,
            "error": "comparison recording no longer accepts input completion",
        });
    }
    serde_json::json!({ "ok": true })
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    if !tokio::fs::try_exists(path).await.with_context(|| {
        format!(
            "failed to inspect recording control socket {}",
            path.display()
        )
    })? {
        return Ok(());
    }
    if UnixStream::connect(path).await.is_ok() {
        return Err(anyhow!(
            "recording control socket is already active: {}",
            path.display()
        ));
    }
    tokio::fs::remove_file(path).await.with_context(|| {
        format!(
            "failed to remove stale recording control socket {}",
            path.display()
        )
    })
}

#[derive(Debug, Clone, Copy)]
enum RecordingWaitTarget {
    Listeners,
    Ready,
}

impl RecordingWaitTarget {
    fn is_satisfied(self, status: &RecordingReadiness) -> bool {
        match self {
            Self::Listeners => status.listeners_bound,
            Self::Ready => status.ready,
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Listeners => "recording listeners",
            Self::Ready => "recording",
        }
    }
}

pub async fn wait_for_recording_listeners(
    config: RecordingWaitConfig,
) -> Result<RecordingReadiness> {
    wait_for_recording_state(config, RecordingWaitTarget::Listeners).await
}

pub async fn wait_for_recording_ready(config: RecordingWaitConfig) -> Result<RecordingReadiness> {
    wait_for_recording_state(config, RecordingWaitTarget::Ready).await
}

async fn wait_for_recording_state(
    config: RecordingWaitConfig,
    target: RecordingWaitTarget,
) -> Result<RecordingReadiness> {
    ensure!(
        !config.timeout.is_zero(),
        "recording readiness timeout must be greater than zero"
    );
    let started = Instant::now();
    let mut next_progress = PROGRESS_INTERVAL;
    let mut observed_control = false;
    let mut last_status: Option<RecordingReadiness> = None;
    info!(
        target = target.description(),
        timeout_seconds = config.timeout.as_secs(),
        control_socket = %config.control_socket_path.display(),
        "waiting for recording readiness"
    );
    loop {
        let elapsed = started.elapsed();
        let remaining = config.timeout.saturating_sub(elapsed);
        if remaining.is_zero() {
            return readiness_timeout(target, config.timeout, last_status.as_ref(), None);
        }
        let request_error = match tokio::time::timeout(
            CONTROL_IO_TIMEOUT.min(remaining),
            request_status(&config.control_socket_path),
        )
        .await
        {
            Ok(Ok(status)) => {
                observed_control = true;
                if matches!(status.phase.as_str(), "failed" | "stopping") {
                    let message = status
                        .error
                        .as_deref()
                        .unwrap_or("recorder stopped before reaching readiness");
                    return Err(anyhow!("{message}: {}", serde_json::to_string(&status)?));
                }
                if target.is_satisfied(&status) {
                    return Ok(status);
                }
                last_status = Some(status);
                None
            }
            Ok(Err(error)) if observed_control => {
                return Err(error).context("recording control disappeared before readiness");
            }
            Ok(Err(error)) => Some(error),
            Err(_) => Some(anyhow!(
                "recording control request timed out after {} seconds",
                CONTROL_IO_TIMEOUT.min(remaining).as_secs_f64()
            )),
        };

        let elapsed = started.elapsed();
        if elapsed >= config.timeout {
            return readiness_timeout(target, config.timeout, last_status.as_ref(), request_error);
        }
        if elapsed >= next_progress {
            info!(
                target = target.description(),
                elapsed_seconds = elapsed.as_secs(),
                timeout_seconds = config.timeout.as_secs(),
                control_socket = %config.control_socket_path.display(),
                "still waiting for recording readiness"
            );
            next_progress += PROGRESS_INTERVAL;
        }
        tokio::time::sleep(DEFAULT_POLL_INTERVAL.min(config.timeout.saturating_sub(elapsed))).await;
    }
}

fn readiness_timeout(
    target: RecordingWaitTarget,
    timeout: Duration,
    last_status: Option<&RecordingReadiness>,
    request_error: Option<anyhow::Error>,
) -> Result<RecordingReadiness> {
    let message = format!(
        "{} did not become ready within {} seconds",
        target.description(),
        timeout.as_secs()
    );
    if let Some(status) = last_status {
        return Err(anyhow!(
            "{message}; last status: {}",
            serde_json::to_string(status)?
        ));
    }
    match request_error {
        Some(error) => Err(error).context(message),
        None => Err(anyhow!(message)),
    }
}

async fn request_status(path: &Path) -> Result<RecordingReadiness> {
    let response = request_control(path, &serde_json::json!({ "command": "status" })).await?;
    response
        .status
        .context("recording control status response omitted status")
}

pub async fn notify_recording_input_complete(path: &Path, delivered: usize) -> Result<()> {
    ensure!(
        delivered > 0,
        "recording input completion requires a positive delivered count"
    );
    request_control(
        path,
        &serde_json::json!({
            "command": "input-complete",
            "delivered": delivered,
        }),
    )
    .await?;
    Ok(())
}

async fn request_control(path: &Path, request: &Value) -> Result<RecordingControlResponse> {
    let stream = UnixStream::connect(path).await.with_context(|| {
        format!(
            "failed to connect recording control socket {}",
            path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    let request =
        serde_json::to_vec(request).context("failed to serialize recording control request")?;
    write_half
        .write_all(&request)
        .await
        .context("failed to write recording control request")?;
    write_half
        .shutdown()
        .await
        .context("failed to finish recording control request")?;
    let mut response_bytes = Vec::new();
    read_half
        .take(CONTROL_REQUEST_LIMIT_BYTES + 1)
        .read_to_end(&mut response_bytes)
        .await
        .context("failed to read recording control response")?;
    ensure!(
        response_bytes.len() <= CONTROL_REQUEST_LIMIT_BYTES as usize,
        "recording control response exceeds {CONTROL_REQUEST_LIMIT_BYTES} bytes"
    );
    let response: RecordingControlResponse = serde_json::from_slice(&response_bytes)
        .context("failed to parse recording control response")?;
    ensure!(
        response.ok,
        "recording control request failed: {}",
        response
            .error
            .as_deref()
            .unwrap_or("unknown control response error")
    );
    Ok(response)
}

fn bound_error(error: String) -> String {
    const MAX_ERROR_CHARS: usize = 2048;
    if error.chars().count() <= MAX_ERROR_CHARS {
        return error;
    }
    let mut bounded = error.chars().take(MAX_ERROR_CHARS).collect::<String>();
    bounded.push('…');
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AppConfig {
        let mut config: AppConfig = toml::from_str("").unwrap();
        config.http.enabled = false;
        config.dns_mock.enabled = true;
        config.tcp_gateway.enabled = true;
        config.udp_gateway.enabled = false;
        config.http_gateway.enabled = true;
        config.http_gateway.ready.enabled = true;
        config.mysql.enabled = false;
        config
    }

    #[test]
    fn readiness_requires_every_listener_and_the_source_probe() {
        let lifecycle = RecordingLifecycle::from_config(&test_config());
        assert_eq!(lifecycle.snapshot().phase, "starting");

        lifecycle.mark_listener_ready(RecordingListener::DnsMock);
        lifecycle.mark_listener_ready(RecordingListener::TcpGateway);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
        let listeners_ready = lifecycle.snapshot();
        assert!(listeners_ready.listeners_bound);
        assert_eq!(listeners_ready.phase, "waiting_for_source");

        assert!(lifecycle.mark_upstream_ready(RecordingListener::HttpGateway));
        let settling = lifecycle.snapshot();
        assert!(!settling.ready);
        assert_eq!(settling.phase, "settling");
        assert!(settling.upstreams_pending.is_empty());

        lifecycle.mark_source_ready();
        let ready = lifecycle.snapshot();
        assert!(ready.ready);
        assert_eq!(ready.phase, "ready");
    }

    #[test]
    fn readiness_waits_for_every_enabled_gateway_upstream() {
        let mut config = test_config();
        config.motan_gateway.enabled = true;
        let lifecycle = RecordingLifecycle::from_config(&config);

        lifecycle.mark_listener_ready(RecordingListener::DnsMock);
        lifecycle.mark_listener_ready(RecordingListener::TcpGateway);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
        lifecycle.mark_listener_ready(RecordingListener::MotanGateway);

        assert!(!lifecycle.mark_upstream_ready(RecordingListener::HttpGateway));
        let http_only = lifecycle.snapshot();
        assert_eq!(http_only.phase, "waiting_for_source");
        assert_eq!(http_only.upstreams_ready, vec!["http_gateway"]);
        assert_eq!(http_only.upstreams_pending, vec!["motan_gateway"]);

        assert!(lifecycle.mark_upstream_ready(RecordingListener::MotanGateway));
        let all_upstreams = lifecycle.snapshot();
        assert_eq!(all_upstreams.phase, "settling");
        assert!(all_upstreams.upstreams_pending.is_empty());

        lifecycle.mark_source_ready();
        assert!(lifecycle.snapshot().ready);
    }

    #[tokio::test]
    async fn wait_listeners_returns_before_source_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("recording.sock");
        let lifecycle = RecordingLifecycle::from_config(&test_config());
        let server = RecordingControlServer::start(lifecycle.clone(), socket.clone())
            .await
            .unwrap();
        lifecycle.mark_listener_ready(RecordingListener::DnsMock);
        lifecycle.mark_listener_ready(RecordingListener::TcpGateway);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);

        let response = wait_for_recording_listeners(RecordingWaitConfig {
            control_socket_path: socket,
            timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();

        assert!(response.listeners_bound);
        assert!(!response.source_ready);
        assert!(!response.ready);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn wait_ready_observes_internal_lifecycle_state() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("recording.sock");
        let lifecycle = RecordingLifecycle::from_config(&test_config());
        let server = RecordingControlServer::start(lifecycle.clone(), socket.clone())
            .await
            .unwrap();
        let wait = tokio::spawn(wait_for_recording_ready(RecordingWaitConfig {
            control_socket_path: socket,
            timeout: Duration::from_secs(1),
        }));

        lifecycle.mark_listener_ready(RecordingListener::DnsMock);
        lifecycle.mark_listener_ready(RecordingListener::TcpGateway);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
        assert!(lifecycle.mark_upstream_ready(RecordingListener::HttpGateway));
        lifecycle.mark_source_ready();

        let response = wait.await.unwrap().unwrap();
        assert!(response.ready);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn wait_ready_reports_lifecycle_failure() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("recording.sock");
        let lifecycle = RecordingLifecycle::from_config(&test_config());
        let server = RecordingControlServer::start(lifecycle.clone(), socket.clone())
            .await
            .unwrap();
        lifecycle.mark_failed("listener bind failed");

        let error = wait_for_recording_ready(RecordingWaitConfig {
            control_socket_path: socket,
            timeout: Duration::from_secs(1),
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("listener bind failed"));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn comparison_control_accepts_finite_input_completion() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("comparison.sock");
        let lifecycle = RecordingLifecycle::for_comparison_gateway(true, false, false);
        lifecycle.mark_listener_ready(RecordingListener::HttpGateway);
        let (server, mut completion) =
            RecordingControlServer::start_for_comparison(lifecycle, socket.clone())
                .await
                .unwrap();

        notify_recording_input_complete(&socket, 7).await.unwrap();
        completion.changed().await.unwrap();

        assert_eq!(
            *completion.borrow_and_update(),
            Some(RecordingInputCompletion { delivered: 7 })
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ordinary_recording_control_rejects_input_completion() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("recording.sock");
        let server = RecordingControlServer::start(
            RecordingLifecycle::from_config(&test_config()),
            socket.clone(),
        )
        .await
        .unwrap();

        let error = notify_recording_input_complete(&socket, 1)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not accept finite input completion")
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn wait_ready_times_out_without_a_recorder() {
        let temp = tempfile::tempdir().unwrap();
        let error = wait_for_recording_ready(RecordingWaitConfig {
            control_socket_path: temp.path().join("missing.sock"),
            timeout: Duration::from_millis(25),
        })
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("did not become ready"));
    }
}
