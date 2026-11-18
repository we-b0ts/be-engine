//! Exact ownership changes affecting previous Case delivery scopes.
use crate::{
    model::{ProposedAttribution, RewriteState},
    source,
};
use std::collections::{BTreeMap, BTreeSet};
use traffic_engine::dependency::attribution::DependencyOwner;
use uuid::Uuid;

pub fn observe(
    state: &RewriteState,
    source: &source::SourceSnapshot,
    proposal: &ProposedAttribution,
    moved: &mut BTreeMap<String, BTreeSet<Uuid>>,
    changed_scopes: &mut BTreeSet<String>,
) {
    let next_scope = crate::replay::attribution_scope_key(&proposal.owner);
    for id in &proposal.source_exchange_ids {
        let previous = state
            .dependency_review
            .decisions
            .get(id)
            .map(|decision| &decision.owner)
            .or_else(|| source.case_defaults.get(id))
            .or_else(|| {
                source
                    .exchanges
                    .get(id)
                    .map(|event| &event.capture.attribution)
            });
        if let Some(previous_scope) = previous.map(crate::replay::attribution_scope_key)
            && previous_scope != next_scope
        {
            changed_scopes.insert(previous_scope);
            changed_scopes.insert(next_scope.clone());
        }
        if previous == Some(&proposal.owner)
            || matches!((previous,&proposal.owner),(Some(DependencyOwner::Case{origin_case_id:old,..}),DependencyOwner::Case{origin_case_id:new,..}) if old==new)
        {
            continue;
        }
        if let Some(DependencyOwner::Case { origin_case_id, .. }) = previous
            && let Some(api) = source.apis.get(origin_case_id)
        {
            moved.entry(api.clone()).or_default().insert(*id);
        }
    }
}
