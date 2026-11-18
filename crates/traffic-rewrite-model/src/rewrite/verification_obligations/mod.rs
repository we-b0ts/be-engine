use crate::rewrite::*;
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

impl ScopeObligation {
    pub fn pending(&self) -> bool {
        self.completed_by_session.is_none() && self.retired_reason.is_none()
    }
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
    pub fn requirement(self) -> Option<VerificationRequirement> {
        match self {
            Self::Classification => None,
            Self::Runtime => Some(VerificationRequirement::Replay),
            Self::MissingCapture => Some(VerificationRequirement::Capture),
        }
    }
}

pub fn scope_matches_api(scope: &VerificationScope, method_api: &str) -> bool {
    matches!(scope,VerificationScope::Api{api,method,..} if api == crate::rewrite::api_selector::public_api(method_api)
        && method.as_deref().is_none_or(|method|method_api.split_once(' ').is_some_and(|(actual,_)|actual == method)))
}

pub fn blocks_api(obligations: &BTreeMap<String, ScopeObligation>, api: &str) -> bool {
    obligations
        .values()
        .any(|obligation| obligation.pending() && scope_matches_api(&obligation.scope, api))
}
