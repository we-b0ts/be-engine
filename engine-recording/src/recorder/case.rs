use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseInvalidation {
    pub reason: String,
    pub message: String,
    pub context: Option<CaseInvalidationContext>,
    recovery: CaseFailureRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseFailureRecovery {
    StopSource,
    AfterDependencyDrain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseInvalidationContext {
    pub category: String,
    pub elapsed_ms: u128,
    pub recorder_phase: String,
    #[serde(flatten)]
    pub native: std::collections::BTreeMap<String, serde_json::Value>,
}

impl CaseInvalidation {
    pub fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
            context: None,
            recovery: CaseFailureRecovery::StopSource,
        }
    }

    pub fn with_context(mut self, context: CaseInvalidationContext) -> Self {
        self.context = Some(context);
        self
    }

    /// A capture owner may permit local archival; the lifecycle must still prove
    /// protocol-proven primary teardown, complete dependency drain and publication.
    pub fn allow_drained_case_recovery(mut self) -> Self {
        self.recovery = CaseFailureRecovery::AfterDependencyDrain;
        self
    }

    pub fn can_recover_after_drain(&self) -> bool {
        self.recovery == CaseFailureRecovery::AfterDependencyDrain
    }

    pub fn prevent_drained_case_recovery(&mut self) {
        self.recovery = CaseFailureRecovery::StopSource;
    }
}

pub use traffic_recording_model::PrimaryCaseDescriptor;
