use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseInvalidation {
    pub(crate) reason: String,
    pub(crate) message: String,
    pub(crate) context: Option<CaseInvalidationContext>,
    recovery: CaseFailureRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseFailureRecovery {
    StopSource,
    AfterDependencyDrain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CaseInvalidationContext {
    pub(crate) category: String,
    pub(crate) elapsed_ms: u128,
    pub(crate) recorder_phase: String,
    #[serde(flatten)]
    pub(crate) native: std::collections::BTreeMap<String, serde_json::Value>,
}

impl CaseInvalidation {
    pub(crate) fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
            context: None,
            recovery: CaseFailureRecovery::StopSource,
        }
    }

    pub(crate) fn with_context(mut self, context: CaseInvalidationContext) -> Self {
        self.context = Some(context);
        self
    }

    /// A capture owner may permit local archival; the lifecycle must still prove
    /// protocol-proven primary teardown, complete dependency drain and publication.
    pub(crate) fn allow_drained_case_recovery(mut self) -> Self {
        self.recovery = CaseFailureRecovery::AfterDependencyDrain;
        self
    }

    pub(crate) fn can_recover_after_drain(&self) -> bool {
        self.recovery == CaseFailureRecovery::AfterDependencyDrain
    }

    pub(crate) fn prevent_drained_case_recovery(&mut self) {
        self.recovery = CaseFailureRecovery::StopSource;
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct PrimaryCaseDescriptor {
    pub(crate) version: u8,
    pub(crate) kind: String,
    pub(crate) api_key: String,
    pub(crate) display_name: String,
    pub(crate) source_binding: serde_json::Value,
}
