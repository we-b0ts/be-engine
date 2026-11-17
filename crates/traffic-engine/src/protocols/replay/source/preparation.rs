//! Native Source loading for the shared portable report preparation pipeline.
use super::*;
use crate::replay::report::global_evidence::preparation::{
    self, PreparedSource, SourcePreparation,
};
use std::sync::Arc;
use traffic_protocol::connection::NativeFuture;

pub struct ReportPreparation {
    rules: Vec<crate::BackgroundDependencyRuleConfig>,
    policy: String,
    providers: Arc<crate::protocols::DependencyProviders>,
}

impl ReportPreparation {
    pub fn new(
        rules: Vec<crate::BackgroundDependencyRuleConfig>,
        fingerprint: Option<&str>,
        providers: Arc<crate::protocols::DependencyProviders>,
    ) -> Result<Self> {
        Ok(Self {
            policy: preparation::policy_identity(&rules, fingerprint)?,
            rules,
            providers,
        })
    }
}

impl SourcePreparation for ReportPreparation {
    fn policy(&self) -> &str {
        &self.policy
    }
    fn validate_record(&self, value: &Value) -> Result<()> {
        super::validate_index_record(value)
    }
    fn load<'a>(&'a self, source: &'a Path) -> NativeFuture<'a, Box<dyn PreparedSource>> {
        Box::pin(async move {
            let source = super::projection::GlobalSource::load_with_providers(
                source,
                &self.rules,
                self.providers.clone(),
            )
            .await?;
            Ok(Box::new(source) as Box<dyn PreparedSource>)
        })
    }
}

impl PreparedSource for super::projection::GlobalSource {
    fn retain_extensions(&self, marker: &Path) -> Result<BTreeMap<String, Value>> {
        self.retain_source_extensions(marker)
    }
}

#[cfg(test)]
pub async fn prewarm_global_report(
    run: &Path,
    rules: &[crate::BackgroundDependencyRuleConfig],
    fingerprint: Option<&str>,
) -> Result<()> {
    preparation::prewarm(
        run,
        Arc::new(ReportPreparation::new(
            rules.to_vec(),
            fingerprint,
            crate::protocols::default_providers(),
        )?),
    )
    .await
}
