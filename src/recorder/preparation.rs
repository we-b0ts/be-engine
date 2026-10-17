//! Best-effort derived indexes, isolated from recording completion semantics.
use super::*;

#[derive(Clone)]
pub(super) struct GlobalPreparation {
    pub rules: Vec<crate::BackgroundDependencyRuleConfig>,
    pub fingerprint: Option<String>,
}
impl Recorder {
    pub(crate) fn with_global_preparation(mut self, config: &crate::AppConfig) -> Self {
        self.global_preparation = Some(Arc::new(GlobalPreparation {
            rules: config.process_owned_dependencies.clone(),
            fingerprint: config.global_projection_policy.clone(),
        }));
        self
    }
    pub(super) async fn prepare_global_report(&self) {
        let Some(options) = &self.global_preparation else {
            return;
        };
        if let Err(error) = crate::replay::report::prewarm_global_report(
            &self.run_dir,
            &options.rules,
            options.fingerprint.as_deref(),
        )
        .await
        {
            tracing::warn!(run_dir=%self.run_dir.display(), error=%error,
                "optional Global report preparation status could not be published; original recording is preserved");
        }
    }
}
