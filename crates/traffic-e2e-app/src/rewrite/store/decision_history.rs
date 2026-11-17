//! Explicit storage maintenance never advances or refreshes workflow semantics.
use std::os::unix::fs::OpenOptionsExt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::rewrite::{RewriteContext, execution, rule_plans, traffic_operation, worker};

pub fn compact_rewrite_decision_history(context: RewriteContext) -> Result<Value> {
    let store = RewriteStore::new(&context.target_root)?;
    let _coordinator = store.lock()?;
    ensure!(
        !execution::busy(&store.target_root)?,
        "decision-history compaction requires an idle coordinator operation"
    );
    ensure!(
        matches!(
            traffic_operation::state(&store.target_root)?,
            traffic_operation::TrafficOperationState::Absent
        ),
        "decision-history compaction requires no active or stale traffic operation"
    );
    let _feedback = worker::events::lock(&store.target_root)?;
    let _plans = rule_plans::events::lock(&store.target_root)?;
    let (original, mut state) = read_raw(&store)?;
    let before = original.len();
    let history = &mut state.dependency_review.decision_history;
    if !history.has_inline_groups() {
        return Ok(report(&state, false, before, before, None));
    }
    // Preserve tolerated extension fields and omitted defaults exactly as JSON
    // values; typed reserialization would change more than storage history.
    let mut document: Value = serde_json::from_slice(&original)?;
    history.verify_archives(
        &store.snapshots.root().join("decision-history"),
        &state.workflow_id,
    )?;
    let backup = backup(&store, &original)?;
    history.persist(
        &store.snapshots.root().join("decision-history"),
        &state.workflow_id,
    )?;
    document["dependency_review"]["decision_history"] = serde_json::to_value(history)?;
    let mut payload = serde_json::to_vec_pretty(&document)?;
    payload.push(b'\n');
    store.write_snapshot(&payload, state.revision)?;
    Ok(report(&state, true, before, payload.len(), Some(backup)))
}

pub fn verify_rewrite_decision_history(context: RewriteContext) -> Result<Value> {
    let store = RewriteStore::new(&context.target_root)?;
    let (bytes, state) = read_raw(&store)?;
    state.dependency_review.decision_history.verify_archives(
        &store.snapshots.root().join("decision-history"),
        &state.workflow_id,
    )?;
    let mut result = report(&state, false, bytes.len(), bytes.len(), None);
    result["verified"] = json!(true);
    Ok(result)
}

fn read_raw(store: &RewriteStore) -> Result<(Vec<u8>, RewriteState)> {
    let bytes = store
        .snapshot_bytes()?
        .context("rewrite workflow has not been initialized")?;
    let state: RewriteState = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "invalid rewrite state {}",
            store.snapshots.state_path().display()
        )
    })?;
    ensure!(
        state.version == STATE_VERSION,
        "unsupported rewrite state version {}",
        state.version
    );
    Ok((bytes, state))
}

fn report(
    state: &RewriteState,
    changed: bool,
    before: usize,
    after: usize,
    backup: Option<PathBuf>,
) -> Value {
    let history = &state.dependency_review.decision_history;
    json!({
        "workflow_id": state.workflow_id,
        "revision": state.revision,
        "changed": changed,
        "state_bytes_before": before,
        "state_bytes_after": after,
        "history_groups": history.group_count(),
        "history_occurrences": history.occurrences(),
        "inline_history": history.has_inline_groups(),
        "backup": backup,
    })
}

fn backup(store: &RewriteStore, bytes: &[u8]) -> Result<PathBuf> {
    let directory = store.snapshots.root().join("history");
    fs::create_dir_all(&directory)?;
    File::open(store.snapshots.root())?.sync_all()?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let destination = directory.join(format!("decision-history-{digest}.json"));
    if destination.exists() {
        ensure!(
            fs::read(&destination)? == bytes,
            "decision-history backup differs from its content identity"
        );
        return Ok(destination);
    }
    let temporary = directory.join(format!(".decision-history-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure!(
                    fs::read(&destination)? == bytes,
                    "decision-history backup differs from its content identity"
                );
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        File::open(&directory)?.sync_all()?;
        Ok(destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests;
