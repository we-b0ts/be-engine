//! Source-only owner rules can be published before the first genuine Replay.
use super::*;
use crate::policy::{CompiledPolicy, NativeEffect};
use serde_json::Value;

const PREFIX: &str = "attribution-evidence-";
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Identity {
    workflow: String,
    recording_run: String,
    source_revision: String,
    source_inventory: String,
    proof_revision: u64,
    engine: String,
    pub(super) case_source: PathBuf,
}

impl Identity {
    pub(super) fn current(state: &RewriteState) -> Result<Self> {
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

pub(super) fn proposal_context(
    input: &str,
    current: &TrafficPolicy,
    state: &RewriteState,
) -> Result<super::proposal_context::Resolved> {
    // A historical document header is a default for its existing rules, not
    // proof that a new owner belongs to that older Source. Bind only newly
    // proposed ownership declarations to the current immutable Source revision;
    // existing effects and their proofs remain untouched.
    let mut context = current.clone();
    context.source_revision = state.source_revision.clone();
    super::proposal_context::resolve(input, &context)
}

pub(in crate::rewrite) fn information(root: &Path, state: &RewriteState) -> Result<Value> {
    let id = Identity::current(state)?.evidence_id()?;
    Ok(
        json!({"evidence_id":id,"scope":"source_attribution","owner":"coordinator",
        "target_observations":false,"accepted":false,
        "allowed":"Source-proven process task ownership and async_api lifecycle rules only; apply independent attribution proof afterwards, then execute genuine Replay",
        "after_analysis":{
            "missing_or_incomplete_policy":"Return a minimal Source-proven rule proposal. The coordinator plans and applies it with this evidence, obtains fresh attribution context, then applies the independent exact-occurrence proof.",
            "existing_policy_sufficient":"Identify the effective rules and explain why they cover the Source path. No unchanged plan/apply is required; retain exact-occurrence proof for historical recordings or policy-execution gaps.",
            "async_api_scope":"Declare request/response triggers and complete terminal end conditions for future recording; do not enumerate intermediate dependency requests.",
            "unavailable_terminal_or_execution_gap":"Report the concrete evidence and remaining recording obligations. Continue the supported independent attribution and genuine Replay path; do not invent a terminal event or add an engine-repair prerequisite."
        },
        "plan_command":action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<source-owner-rule.yaml>".into(),"--evidence".into(),id],vec![])}),
    )
}

pub(super) fn matches(id: &str) -> bool {
    id.starts_with(PREFIX)
}

pub(super) fn plan(
    context: RewriteContext,
    options: RewriteUnifiedRulePlanOptions,
) -> Result<RewriteRuleReport> {
    let (root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&root)?;
    let _lock = store.lock()?;
    let mut state = store.load()?.context("rewrite workflow absent")?;
    ensure!(
        matches!(
            super::super::traffic_operation::state(&root)?,
            super::super::traffic_operation::TrafficOperationState::Absent
        ),
        "finish or recover traffic execution before publishing Source ownership rules"
    );
    ensure!(
        options.evidence_id == Identity::current(&state)?.evidence_id()?,
        "Source attribution assignment or inventory changed; obtain fresh attribution context"
    );
    let _plan_lock = super::super::rule_plans::events::lock_api(&root, &state.api)?;
    let result = super::plan(&root, &mut state, options, false)?;
    store.save(&state)?;
    Ok(result)
}

pub(super) fn validate_proposal(policy: &TrafficPolicy) -> Result<()> {
    ensure!(
        policy
            .rules
            .iter()
            .all(|rule| matches!(rule,PolicyRule::Native(rule)
        if pure_ownership(&rule.effect))),
        "Source attribution planning accepts declared process-task ownership or async_api lifecycle rules only; value, sharing, acquisition and delivery permissions require their own evidence"
    );
    ensure!(
        policy.json.is_none()
            && policy.mysql.is_none()
            && policy.redis.is_none()
            && policy.http.is_none(),
        "Source attribution evidence cannot authorize value formats or payload changes"
    );
    Ok(())
}

fn pure_ownership(effect: &NativeEffect) -> bool {
    let NativeEffect::ProcessOwned(effect) = effect else {
        return false;
    };
    effect.origin.is_none()
        && effect.task_name.is_some()
        && match &effect.selector {
            crate::policy::native::ProcessSelector::Redis {
                initial_load_timeout_ms,
                ..
            } => initial_load_timeout_ms.is_none(),
            // This adapter currently requires an initialization snapshot. Its
            // acquisition permission keeps the ordinary recording workflow.
            crate::policy::native::ProcessSelector::Memcached { .. } => false,
            _ => true,
        }
}

pub(super) fn validate_change(before: &CompiledPolicy, after: &CompiledPolicy) -> Result<()> {
    let mut projected = before.clone();
    projected.native = after.native.clone();
    projected.async_api = after.async_api.clone();
    projected.fingerprints = after.fingerprints.clone();
    ensure!(
        projected == *after,
        "Source attribution cannot change non-ownership contracts"
    );
    for rule in before
        .native
        .iter()
        .chain(after.native.iter())
        .filter(|rule| {
            let other = if before.native.contains(rule) {
                &after.native
            } else {
                &before.native
            };
            !other.contains(rule)
        })
    {
        ensure!(
            pure_ownership(&rule.rule.effect),
            "Source attribution cannot replace or remove a non-ownership rule"
        );
    }
    Ok(())
}
