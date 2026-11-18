use std::{fs, path::Path};

use anyhow::{Result, ensure};
use serde_json::Value;

use super::{WitnessManifest, artifact_path, digest};

/// Keep the authenticated relative artifact reference valid when publishing Replay.
pub fn stage(source_report: &Path, destination_report: &Path) -> Result<()> {
    let report: Value = serde_json::from_slice(&fs::read(source_report)?)?;
    super::hypotheses::stage(source_report, destination_report, &report)?;
    let Some(value) = report.get("policy_witnesses") else {
        return Ok(());
    };
    let manifest: WitnessManifest = serde_json::from_value(value.clone())?;
    if manifest.version == 4 {
        return super::catalog::stage(source_report, destination_report, &manifest);
    }
    if let Some(graph) = &manifest.observations
        && !graph.segments.is_empty()
    {
        return super::storage::stage(source_report, destination_report, graph);
    }
    let source = artifact_path(source_report, &manifest)?;
    let destination = artifact_path(destination_report, &manifest)?;
    let metadata = fs::symlink_metadata(&source)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "policy witness artifact must be regular"
    );
    ensure!(
        digest(&fs::read(&source)?) == manifest.sha256,
        "policy witness artifact changed before publication"
    );
    if source != destination {
        if destination.exists() {
            let metadata = fs::symlink_metadata(&destination)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && digest(&fs::read(&destination)?) == manifest.sha256,
                "policy witness publication collides with another artifact"
            );
        } else {
            fs::copy(&source, &destination)?;
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
