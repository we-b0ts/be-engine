//! Immutable capture policy and actual executable provenance registration.
use super::*;

impl Recorder {
    pub async fn register_capture_policy(
        &mut self,
        identity: String,
        tasks: std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        self.writer
            .set_capture_policy_identity(identity.clone(), tasks)
            .await?;
        self.capture_policy_identity = identity;
        Ok(())
    }

    pub async fn set_source_artifact_identity(
        &self,
        identity: crate::dependency::observation::SourceArtifactIdentity,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        self.writer.set_source_artifact_identity(identity).await
    }
}
