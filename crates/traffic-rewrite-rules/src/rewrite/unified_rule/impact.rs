//! Reuse execution only when its method's effective runtime contract is unchanged.
use crate::policy::CompiledPolicy;
use crate::rewrite::model::RewriteState;
use anyhow::Result;
use std::{collections::BTreeSet, path::Path};

pub fn request_replays(
    state: &mut RewriteState,
    before: &str,
    after: &str,
    proof_id: &str,
) -> Result<()> {
    use crate::rewrite::{
        model::{RewriteApiStatus, RewritePhase},
        verification_obligations::{ScopeObligation, VerificationRequirement, VerificationScope},
    };
    let methods = state
        .api_inventory
        .iter()
        .map(|item| item.api.clone())
        .chain(std::iter::once(state.api.clone()))
        .chain(state.parked_slices.keys().cloned())
        .collect::<BTreeSet<_>>();
    for method_api in methods {
        if !affects_api(before, after, &method_api)? {
            continue;
        }
        state.dependency_review.receipts.remove(&method_api);
        let Some((method, api)) = method_api.split_once(' ') else {
            continue;
        };
        let scope = VerificationScope::Api {
            api: api.into(),
            method: Some(method.into()),
            scenario: None,
        };
        let id = crate::policy_evidence::digest(&serde_json::to_vec(&(
            proof_id,
            &scope,
            VerificationRequirement::Replay,
        ))?);
        state.dependency_review.obligations.insert(id.clone(),ScopeObligation{id,scope,requirement:VerificationRequirement::Replay,
            source_revision:state.source_revision.clone().unwrap_or_default(),baseline_recording_run_id:state.recording_run_id.clone(),
            proof_id:proof_id.into(),reason:"effective runtime contract changed for this method; execute genuine Replay against the same Source".into(),completed_by_session:None,retired_reason:None});
        for slice in std::iter::once(&mut state.active_slice)
            .chain(state.parked_slices.values_mut())
            .filter(|slice| slice.api == method_api)
        {
            slice.e2e_current = false;
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
                item.status = RewriteApiStatus::Pending;
            }
        }
    }
    Ok(())
}

fn compile(input: &str) -> Result<CompiledPolicy> {
    crate::policy::parse_and_compile_policy(input)
}

pub fn affects_api(before: &str, after: &str, method_api: &str) -> Result<bool> {
    let before = compile(before)?;
    let after = compile(after)?;
    if before.fingerprints.runtime == after.fingerprints.runtime {
        return Ok(false);
    }
    let mut projected = before.clone();
    projected.async_api = after.async_api.clone();
    projected.fingerprints = after.fingerprints.clone();
    if projected != after {
        return Ok(true);
    }
    let Some((method, path)) = method_api.split_once(' ') else {
        return Ok(true);
    };
    let changed = before
        .async_api
        .keys()
        .chain(after.async_api.keys())
        .collect::<BTreeSet<_>>();
    Ok(changed
        .into_iter()
        .filter(|api| before.async_api.get(*api) != after.async_api.get(*api))
        .any(|api| {
            api.split_once(' ').is_none_or(|(candidate, pattern)| {
                candidate == method && crate::path_pattern::path_patterns_overlap(pattern, path)
            })
        }))
}

pub fn rebase_unchanged(
    root: &Path,
    state: &mut RewriteState,
    before: &str,
    after: &str,
    previous_identity: &str,
) -> Result<()> {
    let identity = crate::rewrite::fingerprint::replay_identity(root)?;
    let target = crate::rewrite::fingerprint::repository_fingerprint(root)?;
    let mut unchanged = BTreeSet::new();
    for slice in std::iter::once(&mut state.active_slice).chain(state.parked_slices.values_mut()) {
        if slice.replay_identity.as_deref() == Some(previous_identity)
            && !affects_api(before, after, &slice.api)?
        {
            slice.replay_identity = Some(identity.clone());
            if slice.target_fingerprint.is_some() {
                slice.target_fingerprint = Some(target.clone());
            }
            unchanged.insert(slice.api.clone());
        }
    }
    for item in &mut state.api_inventory {
        if unchanged.contains(&item.api) && item.verified_target_fingerprint.is_some() {
            item.verified_target_fingerprint = Some(target.clone());
        }
    }
    for (api, receipt) in &mut state.dependency_review.receipts {
        if unchanged.contains(api) && receipt.execution_identity == previous_identity {
            receipt.execution_identity = identity.clone();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn async_origin_change_does_not_require_replaying_an_unrelated_method() {
        let before = "format: traffic-policy/v3\n";
        let after = "format: traffic-policy/v3\nasync_api:\n  'POST /jobs':\n    - end:\n        - redis: {operation: DEL, key: 'job:done:*'}\n";
        assert!(affects_api(before, after, "POST /jobs").unwrap());
        assert!(!affects_api(before, after, "GET /jobs").unwrap());
        assert!(!affects_api(before, after, "GET /users").unwrap());
    }
}
