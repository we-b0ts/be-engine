//! Independent repository analysis admits genuine batch evidence into one planner.
use super::*;
use serde_json::{Value, json};

const PREFIX: &str = "batch-evidence-";

pub(in crate::rewrite) fn evidence(
    root: &Path,
    state: &RewriteState,
) -> Result<crate::e2e_run::BatchRuleEvidence> {
    let evidence = crate::e2e_run::batch_rule_evidence(crate::E2eRunContext {
        target_root: root.into(),
        case_source: state
            .case_source
            .clone()
            .or_else(|| state.recording_input_case_source.clone())
            .context("batch rule evidence requires current Source inputs")?,
        run_key: None,
    })?;
    ensure!(
        evidence.recording_run_id == state.recording_run_id
            && state
                .source_revision
                .as_ref()
                .is_none_or(|revision| revision == &evidence.source_revision),
        "batch rule evidence belongs to a different workflow Source"
    );
    Ok(evidence)
}

fn id(state: &RewriteState, evidence: &crate::e2e_run::BatchRuleEvidence) -> Result<String> {
    Ok(format!(
        "{PREFIX}{}",
        crate::policy_evidence::digest(&serde_json::to_vec(&(
            &state.workflow_id,
            state.dependency_review.revision,
            evidence
        ))?)
        .trim_start_matches("sha256:")
    ))
}

pub(in crate::rewrite) fn information(root: &Path, state: &RewriteState) -> Result<Value> {
    let evidence = evidence(root, state)?;
    let evidence_id = id(state, &evidence)?;
    Ok(
        json!({"scope":"actual_batch","evidence_id":evidence_id,"diagnosis_owner":"coordinator","source_proof_routing":"Known-owned failures stay with their existing implementation owner. Dispatch a repository analyst only for the engine dependency_attribution_required action with concrete ownerless or disputed Source occurrences.","actual_session_id":evidence.session_id,"report_sha256":evidence.report_sha256,"source_inventory_id":evidence.source_inventory_id,"attribution_snapshot":evidence.dependency_attribution_snapshot,"execution_identity":evidence.execution_identity,"plan_command":action::command(root,vec!["rule".into(),"plan".into(),"--file".into(),"<source-proven-rule.yaml>".into(),"--evidence".into(),evidence_id],vec![]),"acceptance":false,"runtime_changes_require":"one fresh complete actual session"}),
    )
}

pub(super) fn matches(evidence_id: &str) -> bool {
    evidence_id.starts_with(PREFIX)
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
        "finish or recover traffic operations before planning a batch rule"
    );
    let _plan_lock = super::super::rule_plans::events::lock_api(&root, &state.api)?;
    let actual = evidence(&root, &state)?;
    ensure!(
        options.evidence_id == id(&state, &actual)?,
        "batch evidence assignment or Source/proof/execution revision changed; query dependency-attribution batch again"
    );
    let report = super::plan(&root, &mut state, options, true)?;
    store.save(&state)?;
    Ok(report)
}

/// Batch analysis cannot borrow an API implementer's primary/inbound scope.
pub(super) fn validate_proposal(policy: &TrafficPolicy) -> Result<()> {
    for rule in &policy.rules {
        let valid = match rule {
            PolicyRule::Value(rule) => {
                rule.surface != crate::policy::Surface::ApiResponse
                    && rule.selector.api.is_none()
                    && rule.when.is_none()
            }
            PolicyRule::Native(rule) => {
                rule.selector.api.is_none()
                    && rule.when.is_none()
                    && !matches!(
                        rule.effect,
                        crate::policy::NativeEffect::ResponseJwt(_)
                            | crate::policy::NativeEffect::ResponseHeaderDate(_)
                            | crate::policy::NativeEffect::ResponseGenerated(_)
                            | crate::policy::NativeEffect::ResponseBody(_)
                            | crate::policy::NativeEffect::InputJwt(_)
                            | crate::policy::NativeEffect::InputSignedTimestamp(_)
                    )
            }
        };
        ensure!(
            valid,
            "unsupported in batch rule scope: API response/inbound/conditional rules require their real API issue; use an explicit supported dependency resource or global/task declaration"
        );
    }
    Ok(())
}

pub(super) fn request_replay(
    state: &mut RewriteState,
    before: &str,
    after: &str,
    proof: &str,
) -> Result<()> {
    use crate::rewrite::model::RewriteApiStatus;
    let accepted = state
        .api_inventory
        .iter()
        .filter(|api| api.status == RewriteApiStatus::Complete)
        .map(|api| api.api.clone())
        .collect::<BTreeSet<_>>();
    super::impact::request_replays(state, before, after, proof)?;
    for item in &mut state.api_inventory {
        if accepted.contains(&item.api) && item.status == RewriteApiStatus::Pending {
            item.status = RewriteApiStatus::RevalidationPending;
        }
    }
    state.dependency_review.batch_receipt = None;
    state.dependency_review.batch_failure = None;
    state.pre_revalidation_review = None;
    Ok(())
}
