//! Acquisition/classification/sharing proof stays with its complete Source owner.
use super::*;
use crate::config::native_policy::{NativeSourceInventory, NativeSourceScope, SourceObligation};
use crate::policy::{CompiledNativeRule, NativeEffect};
use crate::rewrite::model::RewriteState;
use std::path::PathBuf;

pub use traffic_rewrite_model::rewrite::unified_rule::preflight::source::SourceRecord;

pub fn owns(rule: &CompiledNativeRule) -> bool {
    matches!(
        rule.rule.effect,
        NativeEffect::CaptureHttp(_)
            | NativeEffect::CaptureHttpResponse(_)
            | NativeEffect::ProcessOwned(_)
            | NativeEffect::FiniteSharing(_)
    )
}

pub fn validate_project(root: &Path, policy: &CompiledPolicy) -> Result<()> {
    // This also runs when a transaction removes its final Source effect. A
    // published policy must not make project loading or crash recovery fail.
    let mut projected = crate::config::native_policy::project_source_policy(&policy.native)?;
    projected.async_api = policy.async_api.clone();
    crate::AppConfig::load_with_source_policy(root.join(".traffic-e2e/project.yaml"), &projected)
        .map(|_| ())
        .context("updated Source effects are unsupported by the configured recorder")
}

pub fn verify(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
    previous: &CompiledPolicy,
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) -> Result<()> {
    let rules = policy
        .native
        .iter()
        .filter(|rule| selected.contains(&rule.rule.id) && owns(rule))
        .cloned()
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Ok(());
    }
    let mut record = SourceRecord {
        case_source: state
            .case_source
            .clone()
            .context("Source effect has no immutable recording scope")?,
        source_revision: state
            .source_revision
            .clone()
            .context("Source effect has no revision")?,
        recording_run_id: state.recording_run_id.clone(),
        prepared_cases: bundle.cases.clone(),
        replay_report: (!bundle.replay_path.as_os_str().is_empty())
            .then(|| bundle.replay_path.clone()),
        inventory: NativeSourceInventory {
            recording_root: PathBuf::new(),
            recording_run_id: String::new(),
            digest: String::new(),
            artifact_paths: BTreeSet::new(),
            snapshot: Default::default(),
        },
        rule_ids: rules.iter().map(|rule| rule.rule.id.clone()).collect(),
    };
    let mut proof =
        crate::config::native_policy::validate_source(record.scope(root, &policy.native), &rules)?;
    for (id, count) in &proof.rules {
        ensure!(
            *count > 0,
            "Source effect {id:?} has no complete positive witness"
        );
        *result.rules.entry(id.clone()).or_default() += count;
        result.source_validations += count;
    }
    for path in &proof.inventory.artifact_paths {
        bundle.freeze(path)?;
    }
    // A retained acquisition declaration still proves its complete Source
    // inventory. Only a changed acquisition policy creates a new recapture
    // obligation; an earlier unfinished recording refresh must remain pending.
    if previous.fingerprints.capture == policy.fingerprints.capture
        && state.recording_refresh.is_none()
    {
        proof.obligations.remove(&SourceObligation::FreshRecording);
        proof.pending_effect_evidence.clear();
    }
    record.inventory = proof.inventory;
    result.obligations.extend(proof.obligations);
    result
        .pending_effect_evidence
        .extend(proof.pending_effect_evidence);
    result.source_scope = Some(record);
    Ok(())
}

pub trait SourceRecordMethods: Sized {
    fn scope<'a>(
        &'a self,
        root: &'a Path,
        policy: &'a [CompiledNativeRule],
    ) -> NativeSourceScope<'a>;
    fn ensure_current(
        &self,
        root: &Path,
        policy: &CompiledPolicy,
        validation: Option<std::time::SystemTime>,
    ) -> Result<()>;
}

impl SourceRecordMethods for SourceRecord {
    fn scope<'a>(
        &'a self,
        root: &'a Path,
        policy: &'a [CompiledNativeRule],
    ) -> NativeSourceScope<'a> {
        NativeSourceScope {
            target_root: root,
            case_source: &self.case_source,
            source_revision: &self.source_revision,
            recording_run_id: &self.recording_run_id,
            prepared_cases: &self.prepared_cases,
            replay_report: self.replay_report.as_deref(),
            policy_rules: policy,
        }
    }

    fn ensure_current(
        &self,
        root: &Path,
        policy: &CompiledPolicy,
        validation: Option<std::time::SystemTime>,
    ) -> Result<()> {
        if let Some(validation) = validation
            && !self.inventory.snapshot.path.as_os_str().is_empty()
        {
            return crate::dependency_index::evidence::verify_frozen(
                &self.inventory.recording_root,
                &self.inventory.snapshot,
                validation,
            );
        }
        // Legacy Source plans did not record a complete proof catalog.
        let rules = policy
            .native
            .iter()
            .filter(|rule| self.rule_ids.contains(&rule.rule.id))
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            rules.len() == self.rule_ids.len(),
            "Source effect inventory lost a selected rule"
        );
        let proof = crate::config::native_policy::validate_source(
            self.scope(root, &policy.native),
            &rules,
        )?;
        // Re-enumeration detects newly added or removed Source/descriptor paths,
        // including additions that a saved path-only artifact list cannot notice.
        ensure!(
            proof.inventory == self.inventory,
            "complete Source inventory changed after planning"
        );
        Ok(())
    }
}

pub fn needs_recording(obligations: &BTreeSet<SourceObligation>) -> bool {
    obligations.contains(&SourceObligation::FreshRecording)
}
