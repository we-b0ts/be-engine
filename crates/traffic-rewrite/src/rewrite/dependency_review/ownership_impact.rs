//! Reusing unused evidence cannot silently change another Case's delivered scope.
use super::{model::ProposedAttribution, source, verification};
use crate::{
    dependency::attribution::DependencyOwner,
    rewrite::{
        model::{RewriteApiStatus, RewritePhase, RewriteState},
        verification_obligations::{ScopeObligation, VerificationRequirement, VerificationScope},
    },
};
use anyhow::Result;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

pub(super) fn observe(
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

pub(super) fn invalidate(
    root: &Path,
    state: &mut RewriteState,
    source: &source::SourceSnapshot,
    moved: BTreeMap<String, BTreeSet<Uuid>>,
    revision: u64,
) -> Result<()> {
    for (method_api, ids) in moved {
        let parsed = method_api.parse()?;
        let Ok(selected) = crate::rewrite::inventory::scoped(state, Some(&parsed)) else {
            continue;
        };
        // This is the sole reusable exception: all moved occurrences were
        // genuinely unused in this exact current attempt. Proof never moves a
        // delivered occurrence or rebuilds an old matching allocation.
        if verification::actual(root, &selected, source)
            .is_ok_and(|actual| ids.is_subset(&actual.unused))
        {
            continue;
        }
        let Some((method, api)) = method_api.split_once(' ') else {
            continue;
        };
        let scope = VerificationScope::Api {
            api: api.into(),
            method: Some(method.into()),
            scenario: None,
        };
        let proof_id = format!("ownership-scope-revision-{revision}");
        let id = source::digest(&serde_json::to_vec(&(&proof_id, &scope, &ids))?);
        state.dependency_review.obligations.insert(id.clone(),ScopeObligation{id,scope,requirement:VerificationRequirement::Replay,source_revision:state.source_revision.clone().unwrap_or_default(),baseline_recording_run_id:state.recording_run_id.clone(),proof_id,reason:"effective Case ownership changed for occurrences not proved unused in its current actual attempt; execute against the same Source to establish the new allocation".into(),completed_by_session:None,retired_reason:None});
        state.dependency_review.receipts.remove(&method_api);
        for slice in std::iter::once(&mut state.active_slice)
            .chain(state.parked_slices.values_mut())
            .filter(|slice| slice.api == method_api)
        {
            slice.e2e_current = false;
            slice.target_fingerprint = None;
            if slice.phase == RewritePhase::SliceComplete {
                slice.phase = RewritePhase::ApiPending;
            }
            if slice.phase == RewritePhase::ImplementationRequired {
                slice.rule_replay_pending = true;
            }
        }
        for item in state
            .api_inventory
            .iter_mut()
            .filter(|item| item.api == method_api)
        {
            item.e2e_current = false;
            item.verified_target_fingerprint = None;
            if item.status == RewriteApiStatus::Complete {
                item.status = RewriteApiStatus::RevalidationPending;
            }
        }
    }
    Ok(())
}
