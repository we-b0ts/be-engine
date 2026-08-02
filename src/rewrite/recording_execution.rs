use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct RecordingExecutionMarker {
    pub action_id: String,
    pub run_id: String,
    pub operation: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RecordingExecutionState {
    Absent,
    Live(RecordingExecutionMarker),
    Stale(RecordingExecutionMarker),
}

pub(super) fn state(target_root: &Path) -> Result<RecordingExecutionState> {
    let Some(marker) = load(target_root)? else {
        return Ok(RecordingExecutionState::Absent);
    };
    if process_exists(marker.pid) {
        Ok(RecordingExecutionState::Live(marker))
    } else {
        Ok(RecordingExecutionState::Stale(marker))
    }
}

pub(super) fn publish(target_root: &Path, marker: &RecordingExecutionMarker) -> Result<()> {
    ensure!(
        marker.pid > 0,
        "recording execution marker requires a process id"
    );
    let path = marker_path(target_root);
    let root = path
        .parent()
        .context("recording execution marker has no parent")?;
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create rewrite runtime root {}", root.display()))?;
    let temporary = root.join(format!(
        ".recording-execution.json.tmp.{}.{}",
        std::process::id(),
        marker.pid
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("failed to reserve {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        let mut payload = serde_json::to_vec_pretty(marker)?;
        payload.push(b'\n');
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)
            .with_context(|| format!("failed to publish {}", path.display()))?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub(super) fn clear(target_root: &Path, action_id: &str) -> Result<bool> {
    let Some(marker) = load(target_root)? else {
        return Ok(false);
    };
    ensure!(
        marker.action_id == action_id,
        "recording execution marker belongs to another action"
    );
    fs::remove_file(marker_path(target_root))
        .context("failed to remove recording execution marker")?;
    Ok(true)
}

pub(super) fn clear_stale(target_root: &Path) -> Result<bool> {
    match state(target_root)? {
        RecordingExecutionState::Absent => Ok(false),
        RecordingExecutionState::Live(marker) => {
            anyhow::bail!("recording executor process {} is still active", marker.pid)
        }
        RecordingExecutionState::Stale(_) => {
            fs::remove_file(marker_path(target_root))
                .context("failed to remove stale recording execution marker")?;
            Ok(true)
        }
    }
}

pub(super) fn log_path(target_root: &Path, run_id: &str) -> PathBuf {
    runtime_root(target_root).join(format!("recording-{run_id}.log"))
}

fn load(target_root: &Path) -> Result<Option<RecordingExecutionMarker>> {
    let path = marker_path(target_root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read recording execution {}", path.display()));
        }
    };
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid recording execution {}", path.display()))
        .map(Some)
}

fn marker_path(target_root: &Path) -> PathBuf {
    runtime_root(target_root).join("recording-execution.json")
}

fn runtime_root(target_root: &Path) -> PathBuf {
    target_root.join(".traffic-e2e/local/rewrite")
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_reports_live_and_stale_processes() {
        let target = tempfile::tempdir().unwrap();
        let mut marker = RecordingExecutionMarker {
            action_id: "recording-test".to_string(),
            run_id: "20260802000000".to_string(),
            operation: "record".to_string(),
            pid: std::process::id(),
        };
        publish(target.path(), &marker).unwrap();
        assert!(matches!(
            state(target.path()).unwrap(),
            RecordingExecutionState::Live(_)
        ));

        marker.pid = u32::MAX;
        publish(target.path(), &marker).unwrap();
        assert!(matches!(
            state(target.path()).unwrap(),
            RecordingExecutionState::Stale(_)
        ));
        assert!(clear(target.path(), "recording-test").unwrap());
        assert_eq!(
            state(target.path()).unwrap(),
            RecordingExecutionState::Absent
        );
    }
}
