//! Published evidence for an unrelated API remains readable during focused Replay.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::{
    model::{ActiveRunState, RunLayout},
    store, support,
};

pub(super) fn focused_root(layout: &RunLayout, api: &str) -> Result<PathBuf> {
    let root = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !root.join(".active").exists(),
        "evidence for API {api:?} is unavailable while its attempt is active"
    );
    if layout.active_dir.exists() {
        ensure_unrelated(&layout.active_dir.join("state.yaml"), api)?;
    }
    Ok(root)
}

fn ensure_unrelated(path: &Path, api: &str) -> Result<()> {
    // Missing/ambiguous startup identity cannot authorize concurrent evidence.
    let active: ActiveRunState = store::read_yaml(path)
        .context("cannot identify active Replay scope for evidence access")?;
    ensure!(
        !active.apis.is_empty() && active.apis.iter().all(|a| a.group_id != api),
        "evidence for API {api:?} is unavailable while its attempt is active"
    );
    Ok(())
}
