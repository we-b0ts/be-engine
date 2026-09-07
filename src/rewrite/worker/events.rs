//! Worker feedback has a short transaction independent of the traffic transition.
//! The coordinator snapshot folds in every newer binding update on load and save.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::model::RewriteState;
use super::super::process_output_model::RewriteWorkScope;
use super::model::RewriteWorkerBinding;

#[derive(Default, Serialize, Deserialize)]
struct WorkerUpdates {
    workflow_id: String,
    revision: u64,
    bindings: BTreeMap<String, BindingUpdate>,
}

#[derive(Serialize, Deserialize)]
struct BindingUpdate {
    revision: u64,
    binding: RewriteWorkerBinding,
}

pub(in crate::rewrite) fn lock(target_root: &Path) -> Result<File> {
    let root = root(target_root);
    fs::create_dir_all(&root)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join("worker-updates.lock"))?;
    // Advisory file locking is released by the OS even if a feedback writer exits.
    file.lock()
        .context("failed to lock the worker feedback transaction")?;
    Ok(file)
}

pub(in crate::rewrite) fn overlay(target_root: &Path, state: &mut RewriteState) -> Result<()> {
    let updates = load(target_root)?;
    if updates.workflow_id != state.workflow_id || updates.revision <= state.worker_event_revision {
        return Ok(());
    }
    for (key, update) in updates.bindings {
        if update.revision <= state.worker_event_revision {
            continue;
        }
        // Inventory refreshes may remove items; late snapshots never resurrect them.
        let retained = state.api == key
            || state.api_inventory.iter().any(|item| item.api == key)
            || state
                .process_outputs
                .inventory
                .iter()
                .any(|item| key == format!("process_output:{}", item.id));
        if retained {
            state.worker_bindings.insert(key, update.binding);
        }
    }
    state.revision = state
        .revision
        .saturating_add(updates.revision - state.worker_event_revision);
    state.worker_event_revision = updates.revision;
    Ok(())
}

/// Caller holds the feedback lock and validated the event against the latest state.
pub(in crate::rewrite) fn publish(
    target_root: &Path,
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Result<()> {
    let key = scope.binding_key();
    let binding = state
        .worker_bindings
        .get(&key)
        .context("worker update has no binding")?
        .clone();
    let mut updates = load(target_root)?;
    if updates.workflow_id != state.workflow_id {
        updates = WorkerUpdates {
            workflow_id: state.workflow_id.clone(),
            ..Default::default()
        };
    }
    updates.revision = updates
        .revision
        .max(state.worker_event_revision)
        .checked_add(1)
        .context("worker feedback revision overflow")?;
    updates.bindings.insert(
        key,
        BindingUpdate {
            revision: updates.revision,
            binding,
        },
    );
    let path = root(target_root).join("worker-updates.json");
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(&updates)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(root(target_root))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn load(target_root: &Path) -> Result<WorkerUpdates> {
    let bytes = match fs::read(root(target_root).join("worker-updates.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WorkerUpdates::default());
        }
        Err(error) => return Err(error.into()),
    };
    let updates: WorkerUpdates =
        serde_json::from_slice(&bytes).context("invalid worker feedback snapshot")?;
    ensure!(
        updates
            .bindings
            .values()
            .all(|update| update.revision <= updates.revision),
        "worker feedback snapshot contains a future binding update"
    );
    Ok(updates)
}

fn root(target_root: &Path) -> PathBuf {
    crate::internal_runtime::root(target_root).join("rewrite")
}

#[cfg(test)]
mod tests;
