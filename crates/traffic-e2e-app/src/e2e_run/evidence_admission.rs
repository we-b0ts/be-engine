//! Published evidence for an unrelated API remains readable during focused Replay.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use super::{
    model::{ActiveRunState, RunLayout, RunStatus},
    store, support,
};

pub(super) fn require_response_reports(state: &ActiveRunState) -> Result<()> {
    for (path, missing) in [
        (
            &state.assertions_report,
            "runner-owned assertion evidence is missing",
        ),
        (
            &state.aggregate_report,
            "runner-owned aggregate evidence is missing",
        ),
    ] {
        require_report(state, path, missing)?;
    }
    Ok(())
}

pub(super) fn require_aggregate_report(state: &ActiveRunState) -> Result<()> {
    require_report(
        state,
        &state.aggregate_report,
        "runner-owned aggregate evidence is missing",
    )
}

fn require_report(state: &ActiveRunState, path: &Path, missing: &str) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    if state.status == RunStatus::Interrupted && !state.replay_finalized {
        let executed = state
            .cases
            .iter()
            .filter(|case| case.assertion_passed.is_some())
            .count();
        let failure = state
            .errors
            .last()
            .map(|error| error.chars().take(512).collect::<String>())
            .unwrap_or_else(|| "no runtime failure was retained".into());
        bail!(
            "{missing}: Replay attempt {} was interrupted before finalization after {executed}/{} executed cases; primary rule planning requires a complete finalized Replay. Resource/global rules may use another completed focused attempt, retaining fresh-Replay obligations for unfinished foreign APIs. Diagnose the runtime failure and follow the coordinator's current action; last failure: {failure}",
            state.sequence,
            state.cases.len()
        );
    }
    bail!("{missing}")
}

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
