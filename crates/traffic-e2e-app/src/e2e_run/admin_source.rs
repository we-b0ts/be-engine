use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

use super::config::load_project_config;

#[derive(Debug, Clone)]
pub struct SourceUpgradeOptions {
    pub target_root: PathBuf,
    pub source: crate::KubernetesSourceOptions,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceUpgradeResult {
    pub status: &'static str,
    pub project_config: PathBuf,
    pub previous_source_snapshot_id: String,
    pub previous_source_image_id: String,
    pub source_snapshot: crate::SourceSnapshotReport,
    pub startup: crate::StartupSnapshotReport,
}

pub fn upgrade_source_snapshot(options: SourceUpgradeOptions) -> Result<SourceUpgradeResult> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    let project_config = target_root
        .join(crate::repository::TRAFFIC_E2E_ROOT)
        .join(super::config::PROJECT_CONFIG_FILE);
    let project = load_project_config(&target_root, &project_config)?;
    let _coordinator = crate::rewrite::lock_admin_source_upgrade(&target_root)?;
    let source_upgrade = crate::source_snapshot::begin_kubernetes_source_snapshot_upgrade(
        &target_root,
        &options.source,
    )?;
    let previous_source_snapshot_id = source_upgrade.previous_snapshot_id().to_string();
    let previous_source_image_id = source_upgrade.previous_image_id().to_string();
    let startup = match crate::startup::capture_startup_snapshot(
        &target_root,
        &project.project.target.startup,
    ) {
        Ok(startup) => startup,
        Err(error) => {
            return match source_upgrade.rollback() {
                Ok(()) => Err(error)
                    .context("failed to recapture startup inputs from upgraded source snapshot"),
                Err(rollback_error) => Err(error).context(format!(
                    "failed to recapture startup inputs from upgraded source snapshot and source rollback also failed: {rollback_error:#}"
                )),
            };
        }
    };
    let source_snapshot = source_upgrade.commit();

    Ok(SourceUpgradeResult {
        status: "upgraded",
        project_config,
        previous_source_snapshot_id,
        previous_source_image_id,
        source_snapshot,
        startup,
    })
}
