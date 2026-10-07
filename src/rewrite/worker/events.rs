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
    // Normalize both sources before merging: a newer route-keyed callback must
    // replace the same binding in a method-keyed coordinator snapshot.
    normalize_bindings(state)?;
    let mut updates = load(target_root)?;
    if updates.workflow_id != state.workflow_id || updates.revision <= state.worker_event_revision {
        return Ok(());
    }
    normalize_updates(&mut updates)?;
    for (key, update) in updates.bindings {
        if update.revision <= state.worker_event_revision {
            continue;
        }
        // Retained bindings also carry API expert coverage across recording batches.
        // A removed item without a retained binding must not be resurrected.
        let retained = state.worker_bindings.contains_key(&key)
            || super::super::api_selector::public_api(&state.api) == key
            || state
                .api_inventory
                .iter()
                .any(|item| item.api == key || super::super::api_selector::route(&item.api) == key)
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
    publish_many(target_root, state, std::slice::from_ref(scope))
}

/// Publish a whole expert batch atomically under the same feedback lock.
pub(in crate::rewrite) fn publish_many(
    target_root: &Path,
    state: &RewriteState,
    scopes: &[RewriteWorkScope],
) -> Result<()> {
    let mut updates = load(target_root)?;
    if updates.workflow_id != state.workflow_id {
        updates = WorkerUpdates {
            workflow_id: state.workflow_id.clone(),
            ..Default::default()
        };
    }
    normalize_updates(&mut updates)?;
    updates.revision = updates
        .revision
        .max(state.worker_event_revision)
        .checked_add(1)
        .context("worker feedback revision overflow")?;
    for scope in scopes {
        let key = scope.binding_key();
        let binding = state
            .worker_bindings
            .get(&key)
            .context("worker update has no binding")?
            .clone();
        updates.bindings.insert(
            key,
            BindingUpdate {
                revision: updates.revision,
                binding,
            },
        );
    }
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

fn normalize_updates(updates: &mut WorkerUpdates) -> Result<()> {
    let mut bindings = BTreeMap::<String, BindingUpdate>::new();
    for (key, update) in std::mem::take(&mut updates.bindings) {
        let key = super::super::api_selector::public_api(&key).to_string();
        if let Some(previous) = bindings.get(&key) {
            if previous.revision == update.revision {
                ensure!(
                    previous.binding.agent_handle_fingerprint
                        == update.binding.agent_handle_fingerprint,
                    "multiple workers own API {key}; one route requires one worker"
                );
            }
            if previous.revision >= update.revision {
                continue;
            }
        }
        bindings.insert(key, update);
    }
    updates.bindings = bindings;
    Ok(())
}

fn normalize_bindings(state: &mut RewriteState) -> Result<()> {
    let mut bindings = BTreeMap::<String, RewriteWorkerBinding>::new();
    for (stored_key, binding) in &state.worker_bindings {
        let key = super::super::api_selector::public_api(stored_key).to_string();
        if let Some(previous) = bindings.get(&key) {
            ensure!(
                previous.agent_handle_fingerprint == binding.agent_handle_fingerprint,
                "multiple workers own API {key}; one route requires one worker"
            );
            // A canonical entry represents the adopted scope; an alias must not
            // replace its dispatch, review assignment or retained runtime handle.
            if stored_key != &key {
                continue;
            }
        }
        bindings.insert(key, binding.clone());
    }
    state.worker_bindings = bindings;
    Ok(())
}

fn root(target_root: &Path) -> PathBuf {
    crate::internal_runtime::root(target_root).join("rewrite")
}

#[cfg(test)]
mod tests;
