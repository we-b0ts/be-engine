//! Acquisition/classification/sharing proof stays with its complete Source owner.
use super::*;
use crate::config::native_policy::{NativeSourceInventory, NativeSourceScope, SourceObligation};
use crate::policy::{CompiledNativeRule, NativeEffect};
use crate::rewrite::model::RewriteState;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SourceRecord {
    case_source: PathBuf,
    source_revision: String,
    recording_run_id: String,
    prepared_cases: BTreeMap<String, PathBuf>,
    replay_report: PathBuf,
    inventory: NativeSourceInventory,
    rule_ids: BTreeSet<String>,
}

pub(super) fn owns(rule: &CompiledNativeRule) -> bool {
    matches!(
        rule.rule.effect,
        NativeEffect::CaptureHttp(_)
            | NativeEffect::CaptureBreeze(_)
            | NativeEffect::CaptureHttpResponse(_)
            | NativeEffect::ProcessOwned(_)
            | NativeEffect::FiniteSharing(_)
    )
}

pub(super) fn verify(
    root: &Path,
    state: &RewriteState,
    bundle: &mut Bundle,
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
    // Validate the prospective recorder configuration in memory. Publishing a
    // policy that makes project loading fail would also block crash recovery.
    let mut recorder = crate::AppConfig::load_static(root.join(".traffic-e2e/project.yaml"))?;
    crate::config::native_policy::project_source_policy(&policy.native)?.apply_to(&mut recorder)?;
    recorder
        .validate()
        .context("updated Source effects are unsupported by the configured recorder")?;
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
        replay_report: bundle.replay_path.clone(),
        inventory: NativeSourceInventory {
            recording_root: PathBuf::new(),
            recording_run_id: String::new(),
            digest: String::new(),
            artifact_paths: BTreeSet::new(),
        },
        rule_ids: rules.iter().map(|rule| rule.rule.id.clone()).collect(),
    };
    let proof =
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
    record.inventory = proof.inventory;
    result.obligations.extend(proof.obligations);
    result
        .pending_effect_evidence
        .extend(proof.pending_effect_evidence);
    result.source_scope = Some(record);
    Ok(())
}

impl SourceRecord {
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
            replay_report: &self.replay_report,
            policy_rules: policy,
        }
    }

    pub(super) fn ensure_current(&self, root: &Path, policy: &CompiledPolicy) -> Result<()> {
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

pub(super) fn needs_recording(obligations: &BTreeSet<SourceObligation>) -> bool {
    obligations.contains(&SourceObligation::FreshRecording)
}
