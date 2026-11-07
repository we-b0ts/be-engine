//! Best-effort derived indexes, isolated from recording completion semantics.
use super::*;

#[derive(Clone)]
pub(super) struct GlobalPreparation {
    pub rules: Vec<crate::BackgroundDependencyRuleConfig>,
    pub fingerprint: Option<String>,
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
        let result = tokio::task::spawn_blocking(move || {
            crate::dependency_index::global::seal_recording_scopes(
                &run,
                crate::replay::validate_index_record,
            )
        })
        .await
        .context("recording dependency index task failed")
        .and_then(|result| result);
        if let Err(error) = result {
            tracing::warn!(error=%error, "recording dependency indexes could not be published; Replay will rebuild missing indexes");
        }
    }

    pub(super) async fn prepare_mysql_ownership(&self) {
        let run = self.run_dir.clone();
        let rules = self
            .global_preparation
            .as_ref()
            .map(|p| p.rules.clone())
            .unwrap_or_default();
        let result =
            tokio::task::spawn_blocking(move || crate::api_trigger::seal(&run, &rules)).await;
        match result {
            Ok(Ok(())) => {
                if let Some(owner) = self.artifact_owner {
                    for name in [
                        crate::dependency_index::mysql_transactions::FRAGMENT,
                        ".mysql-ownership.json",
                    ] {
                        let path = self.run_dir.join(name);
                        if path.is_file()
                            && let Err(error) = owner.assign_to(&path).await
                        {
                            tracing::warn!(error=%error, "MySQL preparation ownership assignment failed");
                        }
                    }
                }
            }
            error => {
                tracing::warn!(error=?error, "MySQL transaction preparation failed; first Replay will rebuild it")
            }
        }
    }

    pub(crate) async fn with_global_preparation(
        mut self,
        config: &crate::AppConfig,
    ) -> Result<Self> {
        self.register_capture_policy(config).await?;
        self.global_preparation = Some(Arc::new(GlobalPreparation {
            rules: config.process_owned_dependencies.clone(),
            fingerprint: config.global_projection_policy.clone(),
        }));
        Ok(self)
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
