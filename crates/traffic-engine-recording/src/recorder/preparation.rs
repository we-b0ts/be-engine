//! Best-effort derived indexes, isolated from recording completion semantics.
use super::*;

use traffic_protocol::connection::NativeFuture;

pub trait SourcePreparation: Send + Sync {
    fn evidence(&self) -> &traffic_protocol::evidence::EvidenceRegistry;
    fn validate_record(&self, value: &serde_json::Value) -> Result<()>;
    fn safety_issue(&self, value: &serde_json::Value) -> Option<String>;
    fn indexes<'a>(&'a self, run: &'a Path) -> NativeFuture<'a, Vec<PathBuf>>;
    fn global_report<'a>(&'a self, run: &'a Path) -> NativeFuture<'a, ()>;
}

impl Recorder {
    pub(super) async fn seal_case_dependency_indexes(&self) {
        let run = self.run_dir.clone();
        let owner = self.artifact_owner;
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            if let Some(catalog) = crate::dependency_index::case_recording::seal(&run)?
                && let Some(owner) = owner
            {
                owner.assign_path_to(&catalog)?;
            }
            Ok(())
        })
        .await
        .context("recording Case index task failed")
        .and_then(|result| result);
        if let Err(error) = result {
            tracing::warn!(%error, "Case index catalog could not be published; Replay will build missing indexes");
        }
    }

    pub(super) async fn seal_global_dependency_indexes(&self) {
        let run = self.run_dir.clone();
        let preparation = self.source_preparation.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::dependency_index::global::seal_recording_scopes_with_evidence(
                &run,
                |value| preparation.validate_record(value),
                preparation.evidence(),
            )
        })
        .await
        .context("recording dependency index task failed")
        .and_then(|result| result);
        if let Err(error) = result {
            tracing::warn!(error=%error, "recording dependency indexes could not be published; Replay will rebuild missing indexes");
        }
    }

    pub(super) async fn prepare_source_indexes(&self) {
        match self.source_preparation.indexes(&self.run_dir).await {
            Ok(paths) => {
                if let Some(owner) = self.artifact_owner {
                    for path in paths {
                        if let Err(error) = owner.assign_to(&path).await {
                            tracing::warn!(error=%error, "Source index ownership assignment failed");
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error=%error, "Source index preparation failed; Replay will rebuild derived indexes");
            }
        }
    }

    pub(super) async fn prepare_global_report(&self) {
        if let Err(error) = self.source_preparation.global_report(&self.run_dir).await {
            tracing::warn!(run_dir=%self.run_dir.display(), error=%error,
                "optional Global report preparation status could not be published; original recording is preserved");
        }
    }
}
