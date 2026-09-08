use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::action;
use super::model::{RewriteAction, RewriteTrafficOperationKind, RewriteTrafficOperationView};

pub(super) const RESOURCE: &str = "traffic_runtime";
const RETRY_AFTER_SECONDS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TrafficOperationMarker {
    pub operation_id: String,
    pub kind: TrafficOperationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    pub started_at: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum TrafficOperationKind {
    Recording,
    Replay,
    Comparison,
}

impl From<TrafficOperationKind> for RewriteTrafficOperationKind {
    fn from(value: TrafficOperationKind) -> Self {
        match value {
            TrafficOperationKind::Recording => Self::Recording,
            TrafficOperationKind::Replay => Self::Replay,
            TrafficOperationKind::Comparison => Self::Comparison,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TrafficOperationState {
    Absent,
    Live(TrafficOperationMarker),
    Stale(TrafficOperationMarker),
}

pub(super) enum TrafficOperationClaim {
    Acquired(TrafficOperationGuard),
    Busy(TrafficOperationMarker),
    Stale(TrafficOperationMarker),
}

pub(super) fn claim_current(
    target_root: &Path,
    operation_id: String,
    kind: TrafficOperationKind,
    api: Option<String>,
) -> Result<TrafficOperationClaim> {
    claim(
        target_root,
        TrafficOperationMarker {
            operation_id,
            kind,
            api,
            started_at: Utc::now().to_rfc3339(),
            pid: std::process::id(),
        },
    )
}

pub(super) fn claim(
    target_root: &Path,
    marker: TrafficOperationMarker,
) -> Result<TrafficOperationClaim> {
    ensure!(marker.pid > 0, "traffic operation requires a process id");
    match state(target_root)? {
        TrafficOperationState::Live(active) => Ok(TrafficOperationClaim::Busy(active)),
        TrafficOperationState::Stale(active) => Ok(TrafficOperationClaim::Stale(active)),
        TrafficOperationState::Absent => {
            publish(target_root, &marker)?;
            Ok(TrafficOperationClaim::Acquired(TrafficOperationGuard {
                target_root: target_root.to_path_buf(),
                operation_id: marker.operation_id,
                armed: true,
            }))
        }
    }
}

pub(super) fn state(target_root: &Path) -> Result<TrafficOperationState> {
    let Some(marker) = load(target_root)? else {
        return Ok(TrafficOperationState::Absent);
    };
    if process_exists(marker.pid) {
        Ok(TrafficOperationState::Live(marker))
    } else {
        Ok(TrafficOperationState::Stale(marker))
    }
}

pub(super) fn wait_action(
    target_root: &Path,
    requested_api: Option<String>,
    active: &TrafficOperationMarker,
) -> RewriteAction {
    let active_api = active.api.as_deref().unwrap_or("the workflow");
    let status_api = active.api.as_ref().and(requested_api.as_deref());
    RewriteAction::WaitRequired {
        summary: format!(
            "wait for {RESOURCE}; {active_api} is executing {}",
            kind_label(active.kind)
        ),
        resource: RESOURCE.to_string(),
        requested_api: requested_api.clone(),
        blocking_api: active.api.clone(),
        active_operation: Some(view(active)),
        retry_after_seconds: RETRY_AFTER_SECONDS,
        status: action::status_command_for_api(target_root, status_api),
    }
}

pub(super) fn clear_stale(target_root: &Path) -> Result<bool> {
    match state(target_root)? {
        TrafficOperationState::Absent => Ok(false),
        TrafficOperationState::Live(marker) => anyhow::bail!(
            "{} process {} is still active; inspect `backend-rewrite status`",
            kind_label(marker.kind),
            marker.pid
        ),
        TrafficOperationState::Stale(marker) => clear(target_root, &marker.operation_id),
    }
}

fn kind_label(kind: TrafficOperationKind) -> &'static str {
    match kind {
        TrafficOperationKind::Recording => "recording",
        TrafficOperationKind::Replay => "replay",
        TrafficOperationKind::Comparison => "comparison",
    }
}

pub(super) fn view(marker: &TrafficOperationMarker) -> RewriteTrafficOperationView {
    RewriteTrafficOperationView {
        operation_id: marker.operation_id.clone(),
        kind: marker.kind.into(),
        api: marker.api.clone(),
        started_at: marker.started_at.clone(),
    }
}

fn publish(target_root: &Path, marker: &TrafficOperationMarker) -> Result<()> {
    let path = marker_path(target_root);
    let root = path
        .parent()
        .context("traffic operation marker has no parent")?;
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create rewrite runtime root {}", root.display()))?;
    let temporary = root.join(format!(
        ".traffic-operation.json.tmp.{}.{}",
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

fn clear(target_root: &Path, operation_id: &str) -> Result<bool> {
    let Some(marker) = load(target_root)? else {
        return Ok(false);
    };
    ensure!(
        marker.operation_id == operation_id,
        "traffic operation marker belongs to another operation"
    );
    fs::remove_file(marker_path(target_root))
        .context("failed to remove traffic operation marker")?;
    Ok(true)
}

pub(super) fn clear_owned(target_root: &Path, operation_id: &str) -> Result<bool> {
    clear(target_root, operation_id)
}

fn load(target_root: &Path) -> Result<Option<TrafficOperationMarker>> {
    let path = marker_path(target_root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read traffic operation {}", path.display()));
        }
    };
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid traffic operation {}", path.display()))
        .map(Some)
}

fn marker_path(target_root: &Path) -> PathBuf {
    crate::internal_runtime::root(target_root)
        .join("rewrite")
        .join("traffic-operation.json")
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(super) struct TrafficOperationGuard {
    target_root: PathBuf,
    operation_id: String,
    armed: bool,
}

impl TrafficOperationGuard {
    pub(super) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TrafficOperationGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = clear(&self.target_root, &self.operation_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_operation_is_serialized_and_projects_wait_action() {
        let target = tempfile::tempdir().unwrap();
        let claim = claim_current(
            target.path(),
            "replay-a".to_string(),
            TrafficOperationKind::Replay,
            Some("GET /a".to_string()),
        )
        .unwrap();
        let TrafficOperationClaim::Acquired(_guard) = claim else {
            panic!("first operation was not acquired");
        };
        let busy = claim_current(
            target.path(),
            "comparison-b".to_string(),
            TrafficOperationKind::Comparison,
            Some("GET /b".to_string()),
        )
        .unwrap();
        let TrafficOperationClaim::Busy(active) = busy else {
            panic!("second operation did not observe the live owner");
        };
        let action = wait_action(target.path(), Some("GET /b".to_string()), &active);
        let value = serde_json::to_value(action).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["kind"], "wait_required");
        assert_eq!(value["details"]["resource"], RESOURCE);
        assert_eq!(value["details"]["active_operation"]["api"], "GET /a");
        assert_eq!(
            value["commands"]["wait"]["argv"],
            serde_json::json!([
                "backend-rewrite",
                "--target-root",
                target.path(),
                "wait",
                "--seconds",
                "5"
            ])
        );

        let mut workflow_owner = active;
        workflow_owner.kind = TrafficOperationKind::Recording;
        workflow_owner.api = None;
        let action = wait_action(
            target.path(),
            Some("GET /not-installed-yet".to_string()),
            &workflow_owner,
        );
        let value = serde_json::to_value(action).unwrap();
        assert_eq!(
            value["commands"]["wait"]["argv"],
            serde_json::json!([
                "backend-rewrite",
                "--target-root",
                target.path(),
                "wait",
                "--seconds",
                "5"
            ])
        );
    }
}
