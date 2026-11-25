//! Durable attempt selection and read-only status for a Source event recording.

use std::{
    fs::{self, File, TryLockError},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use traffic_engine_e2e_contract::{
    E2eEventSessionApiProgress, E2eEventSessionCounts, E2eEventSessionPhase,
    E2eEventSessionStatusProgress,
};
use uuid::Uuid;

use super::{
    E2eEventSessionProgress, E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus,
    run_config, store,
};

const LATEST_ATTEMPT: &str = "current-attempt.json";
const ATTEMPT_LOCK: &str = "attempt.lock";
const INITIAL_RESULT: &str = "event-attempt.json";
const FINAL_RESULT: &str = "event-result.json";
pub(super) const PROGRESS: &str = "event-progress.json";

#[derive(Serialize, Deserialize)]
struct ProgressSnapshot<E = E2eEventSessionProgress> {
    #[serde(flatten)]
    events: E,
    #[serde(default)]
    phase: E2eEventSessionPhase,
    #[serde(default)]
    apis: E2eEventSessionApiProgress,
}

pub(super) struct ReplayLock(pub(super) File);

impl Drop for ReplayLock {
    fn drop(&mut self) {
        // A child between fork and exec can still hold a copy of the file
        // descriptor. Unlock the shared file description before closing ours.
        let _ = self.0.unlock();
    }
}

pub(super) fn attempts_root(run_root: &Path, recording_root: &Path) -> PathBuf {
    let digest = Sha256::digest(recording_root.as_os_str().as_encoded_bytes());
    run_root.join("event-sessions").join(format!("{digest:x}"))
}

pub(super) fn begin(
    attempts: &Path,
    attempt_id: Uuid,
    initial: &E2eEventSessionResult,
) -> Result<ReplayLock> {
    let directory = attempts.join(attempt_id.simple().to_string());
    let lock = File::options()
        .write(true)
        .create_new(true)
        .open(directory.join(ATTEMPT_LOCK))?;
    lock.lock()?;
    let lock = ReplayLock(lock);
    store::write_json(&directory.join(INITIAL_RESULT), initial)?;
    publish_progress(initial)?;
    store::write_json(&attempts.join(LATEST_ATTEMPT), &attempt_id)?;
    Ok(lock)
}

pub(super) fn finish(directory: &Path, result: &E2eEventSessionResult) -> Result<()> {
    publish_progress(result)?;
    store::write_json(&directory.join(FINAL_RESULT), result)
}

pub(super) fn publish_progress(result: &E2eEventSessionResult) -> Result<()> {
    store::write_json(
        &result.progress,
        &ProgressSnapshot {
            events: &result.events,
            phase: result.phase,
            apis: result.apis,
        },
    )
}

pub fn status_e2e_event_session(
    target_root: &Path,
    recording_root: &Path,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
) -> Result<E2eEventSessionStatus> {
    inspect_status(target_root, recording_root, run_key, attempt_id).map(|(status, _)| status)
}

/// Resolve a report kept within the selected registered Replay attempt.
pub fn event_session_report(
    target_root: &Path,
    recording_root: &Path,
    run_key: &str,
    attempt_id: Uuid,
) -> Result<PathBuf> {
    let (status, attempts) =
        inspect_status(target_root, recording_root, Some(run_key), Some(attempt_id))?;
    let attempt = status
        .attempt
        .context("registered Replay attempt is missing")?;
    let directory = attempts.join(&attempt.attempt_id);
    ensure!(
        attempt.report.starts_with(&directory),
        "Target report is outside the registered Replay attempt"
    );
    let resolved = attempt
        .report
        .canonicalize()
        .with_context(|| format!("Replay attempt {attempt_id} has no readable Target report"))?;
    let scope = attempts.parent().context("missing Replay attempt scope")?;
    ensure!(
        resolved.starts_with(scope.canonicalize()?.join(directory.strip_prefix(scope)?)),
        "Target report is outside the registered Replay attempt"
    );
    Ok(resolved)
}

fn inspect_status(
    target_root: &Path,
    recording_root: &Path,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
) -> Result<(E2eEventSessionStatus, PathBuf)> {
    let target_root = fs::canonicalize(target_root).context("resolve Target root")?;
    let recording_root = fs::canonicalize(recording_root).context("resolve Source recording")?;
    let run_key = run_config::select_run_key(&recording_root, run_key)?;
    let run_root = crate::internal_runtime::root(&target_root).join(&run_key);
    let attempts = attempts_root(&run_root, &recording_root);
    let selected = match attempt_id {
        Some(id) => Some(id),
        None => read_optional(&attempts.join(LATEST_ATTEMPT))?,
    };
    let Some(id) = selected else {
        return Ok((
            E2eEventSessionStatus {
                state: E2eEventSessionState::NotStarted,
                progress: None,
                attempt: None,
            },
            attempts,
        ));
    };
    let attempt_id = id.simple().to_string();
    let directory = attempts.join(&attempt_id);
    let lock = File::open(directory.join(ATTEMPT_LOCK))
        .with_context(|| format!("unknown attempt {id} for this Source recording and run key"))?;
    let running = match lock.try_lock_shared() {
        Ok(()) => false,
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(error)) => return Err(error).context("inspect event attempt lock"),
    };
    // A terminal result takes precedence even while the writer is releasing its lock.
    let terminal = read_optional::<E2eEventSessionResult>(&directory.join(FINAL_RESULT))?;
    let (state, attempt) = if let Some(result) = terminal {
        let state = if result.passed {
            E2eEventSessionState::Passed
        } else {
            E2eEventSessionState::Failed
        };
        (state, result)
    } else {
        let mut snapshot: E2eEventSessionResult = read_required(&directory.join(INITIAL_RESULT))?;
        let progress: ProgressSnapshot = read_required(&directory.join(PROGRESS))?;
        snapshot.events = progress.events;
        snapshot.phase = progress.phase;
        snapshot.apis = progress.apis;
        let state = if running {
            E2eEventSessionState::Running
        } else {
            E2eEventSessionState::Interrupted
        };
        (state, snapshot)
    };
    ensure!(
        attempt.attempt_id == attempt_id
            && attempt.run_key == run_key
            && attempt.recording_root == recording_root,
        "event attempt identity does not match the selected Source recording"
    );
    Ok((
        E2eEventSessionStatus {
            state,
            progress: Some(E2eEventSessionStatusProgress {
                phase: attempt.phase,
                events: E2eEventSessionCounts {
                    matched: attempt.events.matched,
                    total: attempt.events.total,
                },
                apis: attempt.apis,
            }),
            attempt: Some(attempt),
        },
        attempts,
    ))
}

fn read_required<T: DeserializeOwned>(path: &Path) -> Result<T> {
    read_optional(path)?.with_context(|| format!("missing event attempt state {}", path.display()))
}

fn read_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse event attempt state {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read event attempt state {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests;
