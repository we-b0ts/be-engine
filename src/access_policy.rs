use serde::Serialize;

use crate::config::RecordingAccessPolicy;

mod mysql;

pub(crate) use mysql::{MysqlAccessContext, evaluate_mysql_access};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationClass {
    Read,
    Write,
    Session,
    Unknown,
}

impl OperationClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Session => "session",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessDecision {
    Allow,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessEvaluation {
    pub(crate) decision: AccessDecision,
    pub(crate) matched_rule: Option<String>,
}

impl AccessEvaluation {
    const fn from_decision(decision: AccessDecision) -> Self {
        Self {
            decision,
            matched_rule: None,
        }
    }

    fn allowed_by(rule: impl Into<String>) -> Self {
        Self {
            decision: AccessDecision::Allow,
            matched_rule: Some(rule.into()),
        }
    }
}

pub(crate) const fn decide(
    policy: RecordingAccessPolicy,
    operation: OperationClass,
) -> AccessDecision {
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
