//! Immutable capture policy and actual executable provenance registration.
use super::*;

impl Recorder {
    pub(super) async fn register_capture_policy(
        &mut self,
        config: &crate::AppConfig,
    ) -> Result<()> {
        // Only a digest is persisted: capture configuration may contain private
        // matching rules or sensitive header names.
        let bytes = serde_json::to_vec(&(
            &self.capture_policy_identity,
            &config.recording,
            &config.async_api,
            &config.http_gateway,
            &config.motan_gateway,
            &config.process_owned_dependencies,
            &config.process_dependency_tasks,
        ))?;
        let identity = crate::policy_evidence::digest(&bytes);
        self.writer
            .set_capture_policy_identity(
                identity.clone(),
                config.process_dependency_tasks.clone(),
                config.async_api.clone(),
            )
            .await?;
        self.capture_policy_identity = identity;
        Ok(())
    }

    pub(crate) async fn set_source_artifact_identity(
        &self,
        identity: crate::dependency::observation::SourceArtifactIdentity,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        self.writer.set_source_artifact_identity(identity).await
    }
}
