//! Durable attempt selection and read-only status for a Source event recording.

use std::{
    fs::{self, File, TryLockError},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    E2eEventSessionResult, E2eEventSessionState, E2eEventSessionStatus, run_config, store,
};

const LATEST_ATTEMPT: &str = "current-attempt.json";
const ATTEMPT_LOCK: &str = "attempt.lock";
const INITIAL_RESULT: &str = "event-attempt.json";
const FINAL_RESULT: &str = "event-result.json";
pub(super) const PROGRESS: &str = "event-progress.json";

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
    store::write_json(&directory.join(PROGRESS), &initial.events)?;
    store::write_json(&attempts.join(LATEST_ATTEMPT), &attempt_id)?;
    Ok(lock)
}

pub(super) fn finish(directory: &Path, result: &E2eEventSessionResult) -> Result<()> {
    store::write_json(&directory.join(PROGRESS), &result.events)?;
    store::write_json(&directory.join(FINAL_RESULT), result)
}

pub fn status_e2e_event_session(
    target_root: &Path,
    recording_root: &Path,
    run_key: Option<&str>,
    attempt_id: Option<Uuid>,
) -> Result<E2eEventSessionStatus> {
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
        return Ok(E2eEventSessionStatus {
            state: E2eEventSessionState::NotStarted,
            attempt: None,
        });
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
        snapshot.events = read_required(&directory.join(PROGRESS))?;
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
    Ok(E2eEventSessionStatus {
        state,
        attempt: Some(attempt),
    })
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
