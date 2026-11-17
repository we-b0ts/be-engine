//! Application composition of native indexes and portable Source report projections.
use super::replay::source::preparation::ReportPreparation;
use crate::recorder::{Recorder, preparation::SourcePreparation};
use anyhow::Result;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use traffic_protocol::connection::NativeFuture;

struct Preparation {
    rules: Vec<crate::BackgroundDependencyRuleConfig>,
    report: Option<Arc<ReportPreparation>>,
    evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

pub(crate) fn strict(
    evidence: Arc<traffic_protocol::evidence::EvidenceRegistry>,
) -> Arc<dyn SourcePreparation> {
    Arc::new(Preparation {
        rules: Vec::new(),
        report: None,
        evidence,
    })
}

impl SourcePreparation for Preparation {
    fn safety_issue(&self, value: &serde_json::Value) -> Option<String> {
        self.evidence.recording_safety_issue(value)
    }
    fn validate_record(&self, value: &serde_json::Value) -> Result<()> {
        super::replay::source::validate_index_record(value)
    }
    fn indexes<'a>(&'a self, run: &'a Path) -> NativeFuture<'a, Vec<PathBuf>> {
        let run = run.to_owned();
        let rules = self.rules.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                crate::api_trigger::seal(&run, &rules)?;
                Ok([
                    crate::dependency_index::mysql_transactions::FRAGMENT,
                    ".mysql-ownership.json",
                ]
                .into_iter()
                .map(|name| run.join(name))
                .filter(|path| path.is_file())
                .collect())
            })
            .await?
        })
    }
    fn global_report<'a>(&'a self, run: &'a Path) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            if let Some(report) = &self.report {
                crate::replay::report::global_evidence::preparation::prewarm(run, report.clone())
                    .await?;
            }
            Ok(())
        })
    }
}

impl Recorder {
    #[cfg(any(test, feature = "test-support"))]
    pub async fn with_global_preparation(self, config: &crate::AppConfig) -> Result<Self> {
        self.with_global_preparation_and_providers(config, super::default_providers())
            .await
    }
    pub(crate) async fn with_global_preparation_and_providers(
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
        let rules = config.process_owned_dependencies.clone();
        self.source_preparation = Arc::new(Preparation {
            evidence: Arc::new(providers.evidence().clone()),
            report: Some(Arc::new(ReportPreparation::new(
                rules.clone(),
                config.global_projection_policy.as_deref(),
                providers,
            )?)),
            rules,
        });
        Ok(self)
    }
}
