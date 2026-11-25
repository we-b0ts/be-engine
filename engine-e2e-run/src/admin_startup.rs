use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

use super::run_config::load_project_config;

#[derive(Debug, Clone)]
pub struct StartupSnapshotRecaptureOptions {
    pub target_root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupSnapshotRecaptureResult {
    pub status: &'static str,
    pub project_config: PathBuf,
    pub source_snapshot: PathBuf,
    pub startup: crate::StartupSnapshotReport,
}

pub fn recapture_startup_snapshot(
    options: StartupSnapshotRecaptureOptions,
) -> Result<StartupSnapshotRecaptureResult> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    let project_config = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(super::run_config::PROJECT_CONFIG_FILE);
    let project = load_project_config(&target_root, &project_config)?;
    let source_snapshot = project.project.source.snapshot;
    let startup =
        crate::startup::capture_startup_snapshot(&target_root, &project.project.target.startup)?;
    Ok(StartupSnapshotRecaptureResult {
        status: "recaptured",
        project_config,
        source_snapshot,
        startup,
    })
}
