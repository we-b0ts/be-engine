//! Restrict attribution proposals to Source ownership and lifecycle declarations.
use super::RewriteState;
use crate::policy::{CompiledPolicy, NativeEffect, PolicyRule, TrafficPolicy};
use anyhow::{Result, ensure};

pub fn proposal_context(
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

pub fn validate_proposal(policy: &TrafficPolicy) -> Result<()> {
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

pub fn validate_change(before: &CompiledPolicy, after: &CompiledPolicy) -> Result<()> {
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
