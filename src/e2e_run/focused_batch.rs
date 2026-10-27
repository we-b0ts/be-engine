//! Publish a route session as separate method evidence without replaying cases twice.
use std::{fs, path::Path};

use anyhow::{Result, ensure};

use super::{
    model::{ActiveRunState, RunLayout, RunStatus},
    store,
    support::api_directory,
};

pub(super) fn project(state: &ActiveRunState, api: &str) -> ActiveRunState {
    let mut selected = state.clone();
    selected.apis.retain(|item| item.group_id == api);
    selected.cases.retain(|case| case.group_id == api);
    if let Some(selection) = &mut selected.case_selection {
        selection.project(api);
    }
    // Session-wide dependency/finalization failures remain shared. A response
    // mismatch in another method does not invalidate this method's response gate.
    selected.errors.retain(|error| {
        (!error.starts_with("case ")
            || selected
                .cases
                .iter()
                .any(|case| error.starts_with(&format!("case {} ", case.case_id))))
            && (!error.starts_with("API \"") || error.starts_with(&format!("API {api:?} ")))
    });
    if let Some(item) = selected.apis.first() {
        selected.aggregate_report = item.report_dir.join("aggregate.json");
        selected.assertions_report = item.report_dir.join("assertions.json");
        if state.status != RunStatus::Interrupted {
            selected.status = if item.complete_pass
                && selected.errors.is_empty()
                && selected.replay_finalized
                && selected.aggregate_complete
                && selected.aggregate_clean
            {
                RunStatus::Successful
            } else {
                RunStatus::Failed
            };
        }
    }
    selected
}

pub(super) fn publish(
    global: &RunLayout,
    primary: &RunLayout,
    state: &ActiveRunState,
) -> Result<()> {
    if state.apis.len() <= 1 {
        return store::publish_snapshot(&primary.active_dir, &primary.latest_dir, state);
    }
    // Stage every method before publishing the primary tree. Each projection
    // retains its own case IDs, reports and attempt state for existing readers.
    let mut projections = Vec::new();
    for api in &state.apis {
        let root = global
            .run_root
            .join("focused")
            .join(api_directory(&api.group_id));
        let method_active = root.join(".active");
        let latest = root.join("latest");
        let active = if method_active == primary.active_dir {
            method_active.clone()
        } else {
            root.join(format!(".route-stage-{}", uuid::Uuid::new_v4().simple()))
        };
        if active != primary.active_dir {
            ensure!(
                !method_active.exists(),
                "another focused method attempt is active at {}",
                method_active.display()
            );
            copy_evidence(&primary.active_dir, &active)?;
        }
        let projected = super::assertion_publication::prepare(
            &project(state, &api.group_id),
            &primary.active_dir,
            &active,
            &active,
        )?;
        projections.push((active, latest, projected));
    }
    for (active, latest, projected) in projections {
        store::publish_snapshot(&active, &latest, &projected)?;
    }
    Ok(())
}

fn copy_evidence(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink(),
            "focused evidence must not contain symlinks"
        );
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_evidence(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
