//! Application composition of capture policy and provider validation.
use crate::recorder::{Recorder, preparation::SourcePreparation};
use anyhow::Result;
use std::sync::Arc;

struct Preparation {
    evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

pub fn strict(
    evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
) -> Arc<dyn SourcePreparation> {
    Arc::new(Preparation { evidence })
}

impl SourcePreparation for Preparation {
    fn safety_issue(&self, value: &serde_json::Value) -> Option<String> {
        self.evidence.recording_safety_issue(value)
    }
}

impl Recorder {
    #[cfg(any(test, feature = "test-support"))]
    pub async fn with_global_preparation(self, config: &crate::AppConfig) -> Result<Self> {
        self.with_global_preparation_and_providers(config, super::default_providers())
            .await
    }
    pub async fn with_global_preparation_and_providers(
        mut self,
        config: &crate::AppConfig,
        providers: Arc<super::DependencyProviders>,
    ) -> Result<Self> {
        let bytes = serde_json::to_vec(&(
            &self.capture_policy_identity,
            &config.recording,
            &config.async_api,
            &config.http_gateway,
            &config.process_owned_dependencies,
            &config.process_dependency_tasks,
        ))?;
        self.register_capture_policy(
            crate::policy_evidence::digest(&bytes),
            config.process_dependency_tasks.clone(),
        )
        .await?;
        self.source_preparation = strict(Arc::new(providers.evidence().clone()));
        Ok(self)
    }
}
