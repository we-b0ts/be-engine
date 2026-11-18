use crate::config::RecordingAccessPolicy;

mod mysql;

pub use traffic_protocol::connection::Operation as OperationClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Reject,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEvaluation {
    pub decision: AccessDecision,
    pub matched_rule: Option<String>,
}

impl AccessEvaluation {
    #[allow(dead_code)]
    const fn from_decision(decision: AccessDecision) -> Self {
        Self {
            decision,
            matched_rule: None,
        }
    }

    #[allow(dead_code)]
    fn allowed_by(rule: impl Into<String>) -> Self {
        Self {
            decision: AccessDecision::Allow,
            matched_rule: Some(rule.into()),
        }
    }
}

pub const fn decide(policy: RecordingAccessPolicy, operation: OperationClass) -> AccessDecision {
    match (policy, operation) {
        (RecordingAccessPolicy::BlockKnownWrites, OperationClass::Write) => AccessDecision::Reject,
        _ => AccessDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_every_operation_class() {
        for operation in [
            OperationClass::Read,
            OperationClass::Write,
            OperationClass::Session,
            OperationClass::Unknown,
        ] {
            assert_eq!(
                decide(RecordingAccessPolicy::Unrestricted, operation),
                AccessDecision::Allow
            );
        }
    }

    #[test]
    fn block_known_writes_only_rejects_write() {
        assert_eq!(
            decide(
                RecordingAccessPolicy::BlockKnownWrites,
                OperationClass::Write
            ),
            AccessDecision::Reject
        );
        for operation in [
            OperationClass::Read,
            OperationClass::Session,
            OperationClass::Unknown,
        ] {
            assert_eq!(
                decide(RecordingAccessPolicy::BlockKnownWrites, operation),
                AccessDecision::Allow
            );
        }
    }
}
