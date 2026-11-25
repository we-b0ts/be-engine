use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::super::{FAST_CASE_TIMEOUT, ReplayProtocolSet, RuntimeState};
use super::{Lease, TimerEventKind, plan::valid_name};

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME_BYTES: usize = 4096;
const MAX_CLIENTS: usize = 64;

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub(super) version: u16,
    pub(super) case_id: String,
    pub(super) site: String,
    pub(super) stream: String,
    pub(super) occurrence: u64,
    pub(super) consumed_through: u64,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize, PartialEq, Eq))]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Outcome {
    Wake,
    WallClock,
    Error { message: String },
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Completion {
    End,
}

pub(in crate::replay) struct Listener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl Listener {
    pub(in crate::replay) fn bind(path: &Path) -> Result<Self> {
        let listener = UnixListener::bind(path)
            .with_context(|| format!("bind Replay timer socket {}", path.display()))?;
        let metadata = fs::symlink_metadata(path)?;
        let bound = Self {
            listener,
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(bound)
    }

    pub(in crate::replay) async fn run<P: ReplayProtocolSet>(
        self,
        state: Arc<Mutex<RuntimeState<P>>>,
    ) -> Result<()> {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept(), if clients.len() < MAX_CLIENTS => {
                    let (stream, _) = accepted.context("accept Replay timer client")?;
                    clients.spawn(serve(stream, state.clone()));
                }
                result = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::warn!(%error, "Replay timer client task failed");
                    }
                }
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

async fn serve<P: ReplayProtocolSet>(stream: UnixStream, state: Arc<Mutex<RuntimeState<P>>>) {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let result = serve_wait(&mut read, &mut write, &state).await;
    if let Err(error) = result {
        tracing::debug!(%error, "Replay timer wait ended early");
        let outcome = Outcome::Error {
            message: error.to_string(),
        };
        let _ = timeout(FRAME_TIMEOUT, write_frame(&mut write, &outcome)).await;
    }
}

async fn serve_wait<P: ReplayProtocolSet>(
    read: &mut (impl AsyncBufRead + Unpin),
    write: &mut (impl AsyncWrite + Unpin),
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Result<()> {
    let request: Registration = timeout(FRAME_TIMEOUT, read_frame(read)).await??;
    ensure!(
        request.version == 1,
        "unsupported Replay timer protocol version"
    );
    ensure!(
        valid_name(&request.case_id)
            && valid_name(&request.site)
            && valid_name(&request.stream)
            && request.occurrence != 0,
        "invalid Replay timer registration"
    );
    let lease = {
        let mut state = state.lock().await;
        ensure!(
            timer_sequence(&state, &request.case_id).is_some()
                && state.finalized_at.is_none()
                && !state.target_session_stopped
                && !state.async_case_quiescing(),
            "Replay timer requires a live active Case"
        );
        let epoch = state.admission_epoch;
        let sequence = timer_sequence(&state, &request.case_id);
        state.timers.register(&request, epoch, sequence)?
    };
    let Some(mut lease) = lease else {
        return timeout(FRAME_TIMEOUT, write_frame(write, &Outcome::WallClock)).await?;
    };

    let result = match timeout(FAST_CASE_TIMEOUT, drive(&mut lease, read, write, state)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("Replay timer wait timed out")),
    };
    if result.is_err() {
        let mut state = state.lock().await;
        if state.admission_epoch == lease.epoch {
            let _ = state.timers.record(&lease, TimerEventKind::Cancelled);
        }
    }
    result
}

async fn drive<P: ReplayProtocolSet>(
    lease: &mut Lease,
    read: &mut (impl AsyncBufRead + Unpin),
    write: &mut (impl AsyncWrite + Unpin),
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Result<()> {
    loop {
        let frontier = {
            let mut state = state.lock().await;
            ensure_live(&state, lease)?;
            let Some(frontier) = lease
                .sequence
                .wait_for_frontier(lease.step.anchor.sequence())
            else {
                ensure!(
                    lease.at_frontier()?,
                    "Replay timer anchor has an unexpected event kind"
                );
                state.timers.record(lease, TimerEventKind::Wake)?;
                break;
            };
            frontier
        };
        tokio::select! {
            _ = frontier.changed() => {}
            result = lease.scope_changed.changed() => { result?; }
            result = read.fill_buf() => {
                ensure!(result?.is_empty(), "unexpected Replay timer frame before wake");
                bail!("Target cancelled its timer wait");
            }
        }
    }

    timeout(FRAME_TIMEOUT, write_frame(write, &Outcome::Wake)).await??;
    let result: Completion = tokio::select! {
        result = timeout(FRAME_TIMEOUT, read_frame(read)) => result??,
        _ = lease.scope_changed.changed() => bail!("Replay timer Case ended before completion"),
    };
    match result {
        Completion::End => {
            let mut state = state.lock().await;
            ensure_live(&state, lease)?;
            lease
                .sequence
                .release_event_gate(lease.step.anchor.sequence())?;
            state.timers.record(lease, TimerEventKind::End)
        }
    }
}

fn ensure_live<P: ReplayProtocolSet>(state: &RuntimeState<P>, lease: &Lease) -> Result<()> {
    ensure!(
        state.admission_epoch == lease.epoch
            && timer_sequence(state, &lease.case_id)
                .is_some_and(|sequence| Arc::ptr_eq(&sequence, &lease.sequence))
            && state.finalized_at.is_none()
            && !state.target_session_stopped
            && !state.async_case_quiescing(),
        "Replay timer Case ended or changed"
    );
    Ok(())
}

fn timer_sequence<P: ReplayProtocolSet>(
    state: &RuntimeState<P>,
    scope: &str,
) -> Option<Arc<traffic_replay::SequenceRuntime>> {
    if let Some(session) = &state.session_events {
        return (scope == super::super::session::TIMER_SCOPE).then(|| session.runtime.clone());
    }
    (state.active_case_id.as_deref() == Some(scope))
        .then(|| state.active_sequence.clone())
        .flatten()
}

pub(super) async fn read_frame<T: DeserializeOwned>(
    reader: &mut (impl AsyncBufRead + Unpin),
) -> Result<T> {
    let mut frame = Vec::new();
    reader
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_until(b'\n', &mut frame)
        .await?;
    ensure!(
        frame.len() <= MAX_FRAME_BYTES,
        "Replay timer frame is too large"
    );
    ensure!(
        frame.pop() == Some(b'\n'),
        "Replay timer peer closed without a complete frame"
    );
    serde_json::from_slice(&frame).context("invalid Replay timer frame")
}

pub(super) async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> Result<()> {
    let mut frame = serde_json::to_vec(value)?;
    ensure!(
        frame.len() < MAX_FRAME_BYTES,
        "Replay timer frame is too large"
    );
    frame.push(b'\n');
    stream.write_all(&frame).await?;
    Ok(())
}
