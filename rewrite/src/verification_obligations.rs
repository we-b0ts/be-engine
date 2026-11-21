//! Scope-owned verification debt; recording changes never invalidate unrelated APIs.
use std::collections::BTreeMap;

pub use traffic_rewrite_model::rewrite::verification_obligations::VerificationScope;

pub use traffic_rewrite_model::rewrite::verification_obligations::VerificationRequirement;

pub use traffic_rewrite_model::rewrite::verification_obligations::ScopeObligation;

pub(super) use traffic_rewrite_model::rewrite::verification_obligations::blocks_api;

pub(super) use traffic_rewrite_model::rewrite::verification_obligations::scope_matches_api;

pub(super) fn request_capture(
    state: &mut super::model::RewriteState,
    scopes: &BTreeMap<String, String>,
    proof_id: &str,
) -> anyhow::Result<()> {
    for (api, reason) in scopes {
        let scope = VerificationScope::Api {
            api: super::api_selector::public_api(api).into(),
            method: api.split_once(' ').map(|(method, _)| method.into()),
            scenario: None,
        };
        let id = crate::policy_evidence::digest(&serde_json::to_vec(&(
            proof_id,
            &scope,
            VerificationRequirement::Capture,
        ))?);
        state.dependency_review.obligations.insert(
            id.clone(),
            ScopeObligation {
                id,
                scope,
                requirement: VerificationRequirement::Capture,
                source_revision: state.source_revision.clone().unwrap_or_default(),
                baseline_recording_run_id: state.recording_run_id.clone(),
                proof_id: proof_id.into(),
                reason: reason.clone(),
                completed_by_session: None,
                retired_reason: None,
            },
        );
    }
    if !scopes.is_empty() {
        state.dependency_review.revision += 1;
    }
    Ok(())
}

pub use traffic_rewrite_model::rewrite::verification_obligations::VerificationImpact;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_origin_capture_does_not_block_victim_api() {
        let obligation = ScopeObligation {
            id: "origin-a".into(),
            scope: VerificationScope::Api {
                api: "/a".into(),
                method: Some("POST".into()),
                scenario: None,
            },
            requirement: VerificationRequirement::Capture,
            source_revision: "source".into(),
            baseline_recording_run_id: "original".into(),
            proof_id: "proof".into(),
            reason: "terminal Source exchange absent".into(),
            completed_by_session: None,
            retired_reason: None,
        };
        let obligations = BTreeMap::from([(obligation.id.clone(), obligation)]);
        assert!(blocks_api(&obligations, "POST /a"));
        assert!(!blocks_api(&obligations, "GET /b"));
    }
}
