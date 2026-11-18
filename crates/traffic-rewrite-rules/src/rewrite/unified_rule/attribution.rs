use super::*;
const PREFIX: &str = "attribution-evidence-";
pub use traffic_rewrite_model::rewrite::unified_rule::attribution::Identity;
pub trait IdentityMethods: Sized {
    fn current(state: &RewriteState) -> Result<Self>;
    fn evidence_id(&self) -> Result<String>;
}

impl IdentityMethods for Identity {
    fn current(state: &RewriteState) -> Result<Self> {
        let source = state
            .case_source
            .as_deref()
            .context("Source attribution requires a sealed recording")?;
        let (case_source, manifest) = crate::dependency_index::recording::manifest(source)?;
        crate::dependency_index::recording::authenticate(&case_source)?;
        ensure!(
            manifest.run_id == state.recording_run_id,
            "Source attribution recording changed"
        );
        Ok(Self {
            workflow: state.workflow_id.clone(),
            recording_run: state.recording_run_id.clone(),
            source_revision: state
                .source_revision
                .clone()
                .context("Source revision absent")?,
            source_inventory: crate::policy_evidence::digest(&fs::read(
                case_source.join(crate::dependency::observation::MANIFEST_FILE),
            )?),
            proof_revision: state.dependency_review.revision,
            engine: crate::build_info::ENGINE_FINGERPRINT.into(),
            case_source: fs::canonicalize(case_source)?,
        })
    }
    fn evidence_id(&self) -> Result<String> {
        Ok(format!(
            "{PREFIX}{}",
            crate::policy_evidence::digest(&serde_json::to_vec(self)?)
                .trim_start_matches("sha256:")
        ))
    }
}
