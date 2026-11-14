//! Source ownership decisions. These types never represent Replay consumption.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencyOwner {
    Startup {
        process_epoch: Uuid,
        initialization_unit: String,
    },
    Case {
        origin_case_id: Uuid,
        #[serde(skip_serializing_if = "Option::is_none")]
        task_instance: Option<String>,
    },
    Process {
        process_epoch: Uuid,
        source_task: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        invocation: Option<String>,
    },
    /// Recorder-owned teardown associated at the first shutdown boundary.
    /// This is a run scope, not another executable primary Case.
    Shutdown {
        process_epoch: Uuid,
        origin_case_id: Uuid,
    },
    Unattributed {
        reason: String,
    },
}

impl DependencyOwner {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Startup {
                initialization_unit,
                ..
            } => bounded(initialization_unit, "initialization unit"),
            Self::Case {
                origin_case_id,
                task_instance,
            } => {
                ensure!(
                    !origin_case_id.is_nil(),
                    "origin Case identity must be nonzero"
                );
                if let Some(task) = task_instance {
                    bounded(task, "task instance")?;
                }
                Ok(())
            }
            Self::Process {
                source_task,
                invocation,
                ..
            } => {
                bounded(source_task, "Source task")?;
                if let Some(invocation) = invocation {
                    bounded(invocation, "task invocation")?;
                }
                Ok(())
            }
            Self::Unattributed { reason } => bounded(reason, "unattributed reason"),
            Self::Shutdown {
                process_epoch,
                origin_case_id,
            } => {
                ensure!(
                    !process_epoch.is_nil() && !origin_case_id.is_nil(),
                    "shutdown requires a nonzero process epoch and original running Case"
                );
                Ok(())
            }
        }
    }
}

fn bounded(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value == value.trim()
            && value.len() <= 1024
            && !value.chars().any(char::is_control),
        "{label} requires bounded nonempty text without control characters"
    );
    Ok(())
}

/// A proof concerns Source provenance, never whether Target delivered a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionProof {
    pub source_revision: String,
    pub source_locations: Vec<String>,
    pub call_chain: String,
    pub exclusive_scope: String,
}

impl AttributionProof {
    pub fn validate(&self, source_revision: &str) -> Result<()> {
        ensure!(
            self.source_revision == source_revision,
            "attribution proof Source revision is stale"
        );
        ensure!(
            (1..=64).contains(&self.source_locations.len()),
            "attribution proof requires 1..64 Source locations"
        );
        for location in &self.source_locations {
            bounded(location, "Source location")?;
        }
        bounded(&self.call_chain, "Source call chain")?;
        bounded(&self.exclusive_scope, "exclusive ownership scope")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionDecision {
    pub exchange_id: Uuid,
    pub owner: DependencyOwner,
    pub proof_id: String,
    pub proof_revision: u64,
    pub proof: AttributionProof,
    pub rule_bindings: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_does_not_contain_or_accept_consumption_facts() {
        let proof = serde_json::json!({
            "source_revision":"source-v2", "source_locations":["src/jobs.rs:run"],
            "call_chain":"startup launches refresh_keys", "exclusive_scope":"refresh_keys only",
            "consumed":true
        });
        assert!(serde_json::from_value::<AttributionProof>(proof).is_err());
    }

    #[test]
    fn changed_source_invalidates_provenance() {
        let proof = AttributionProof {
            source_revision: "source-v2".into(),
            source_locations: vec!["src/jobs.rs:run".into()],
            call_chain: "startup launches refresh_keys".into(),
            exclusive_scope: "refresh_keys only".into(),
        };
        assert!(proof.validate("source-v2").is_ok());
        assert!(proof.validate("source-v3").is_err());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyScope {
    Startup,
    Process,
    Case,
    /// Original ambient input evidence has no proven business owner.
    Unattributed,
}

impl DependencyScope {
    pub fn is_run_owned(self) -> bool {
        matches!(self, Self::Startup | Self::Process)
    }
    pub fn is_run_level(self) -> bool {
        self != Self::Case
    }
    pub fn matches_scope(self, requested: Self) -> bool {
        self == requested || self.is_run_owned() && requested.is_run_owned()
    }
}
