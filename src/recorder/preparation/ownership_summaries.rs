//! Refresh disposable Case projections after ownership changes their membership.
use super::*;
use crate::dependency::observation::{MANIFEST_FILE, RecordingManifest};
use anyhow::ensure;
use serde::Deserialize;

#[derive(Deserialize)]
struct Receipt {
    assignments: Vec<Assignment>,
    unresolved: Vec<Unresolved>,
}

#[derive(Deserialize)]
struct Assignment {
    assignment: Owner,
    original_capture: OriginalCapture,
}

#[derive(Deserialize)]
struct Unresolved {
    original_capture: OriginalCapture,
}

#[derive(Deserialize)]
struct OriginalCapture {
    attribution: OriginalOwner,
}

#[derive(Deserialize)]
struct OriginalOwner {
    origin_case_id: Option<uuid::Uuid>,
}

#[derive(Deserialize)]
struct Owner {
    case_id: uuid::Uuid,
}

impl Recorder {
    pub(in crate::recorder) async fn refresh_ownership_summaries(&self) -> Result<()> {
        let receipt = self.run_dir.join("dependency-ownership.json");
        if !receipt.try_exists()? {
            return Ok(());
        }
        let root = self.run_dir.clone();
        let directories = tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>> {
            // Deserialize only membership fields; original payloads and the full
            // receipt do not need to be retained for these derived counts.
            let receipt: Receipt = serde_json::from_reader(std::fs::File::open(receipt)?)?;
            let mut affected = BTreeSet::new();
            for entry in receipt.assignments {
                affected.insert(entry.assignment.case_id);
                affected.extend(entry.original_capture.attribution.origin_case_id);
            }
            for entry in receipt.unresolved {
                affected.extend(entry.original_capture.attribution.origin_case_id);
            }
            let manifest: RecordingManifest =
                serde_json::from_reader(std::fs::File::open(root.join(MANIFEST_FILE))?)?;
            ensure!(
                manifest.sealed,
                "ownership summaries require a sealed recording"
            );
            let mut directories = Vec::new();
            for input in manifest.inputs {
                if !affected.remove(&input.case_id) {
                    continue;
                }
                let relative = Path::new(&input.path);
                ensure!(
                    !relative.is_absolute()
                        && relative
                            .components()
                            .all(|part| { matches!(part, std::path::Component::Normal(_)) }),
                    "ownership summary input escapes its recording"
                );
                directories.push(root.join(relative));
            }
            ensure!(
                affected.is_empty(),
                "ownership summary Case is absent from its recording"
            );
            Ok(directories)
        })
        .await
        .context("ownership summary preparation task failed")??;
        for directory in directories {
            super::super::summary::write_case_dependency_summary(&directory).await?;
        }
        Ok(())
    }
}
