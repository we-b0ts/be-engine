//! Scope-owned verification debt; recording changes never invalidate unrelated APIs.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationScope {
    Api {
        api: String,
        method: Option<String>,
        scenario: Option<usize>,
    },
    Process {
        source_task: String,
        process_epoch: Uuid,
    },
    Startup {
        initialization_unit: String,
        process_epoch: Uuid,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRequirement {
    Replay,
    Capture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeObligation {
    pub id: String,
    pub scope: VerificationScope,
    pub requirement: VerificationRequirement,
    pub source_revision: String,
    pub baseline_recording_run_id: String,
    pub proof_id: String,
    pub reason: String,
    pub completed_by_session: Option<String>,
    /// Withdrawal retires a superseded proof obligation without inventing execution.
    pub retired_reason: Option<String>,
}

impl ScopeObligation {
    pub(crate) fn pending(&self) -> bool {
        self.completed_by_session.is_none() && self.retired_reason.is_none()
    }
}

pub(super) fn blocks_api(obligations: &BTreeMap<String, ScopeObligation>, api: &str) -> bool {
    obligations
        .values()
        .any(|obligation| obligation.pending() && scope_matches_api(&obligation.scope, api))
}

pub(super) fn scope_matches_api(scope: &VerificationScope, method_api: &str) -> bool {
    matches!(scope,VerificationScope::Api{api,method,..} if api == super::api_selector::public_api(method_api)
        && method.as_deref().is_none_or(|method|method_api.split_once(' ').is_some_and(|(actual,_)|actual == method)))
}

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

/// A pure unused overlay can reuse real execution. Any delivery/admission effect
/// requires new execution; Capture is required only for genuinely absent Source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationImpact {
    Classification,
    Runtime,
    MissingCapture,
}

impl VerificationImpact {
    pub(crate) fn requirement(self) -> Option<VerificationRequirement> {
        match self {
            Self::Classification => None,
            Self::Runtime => Some(VerificationRequirement::Replay),
            Self::MissingCapture => Some(VerificationRequirement::Capture),
        }
    }
}

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
