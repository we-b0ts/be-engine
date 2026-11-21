//! Small ordered audit references; finite occurrence bodies live in immutable archives.
pub mod archive;
pub mod serde;
#[cfg(test)]
pub mod tests;

use super::{DecisionGroup, DecisionTemplate};
use ::serde::{Deserialize, Serialize};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryOrigin {
    pub workflow_id: String,
    pub recording_run_id: String,
    pub source_inventory_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryArchiveRef {
    archived_from_workflow: String,
    sha256: String,
    byte_length: u64,
    occurrences: u64,
    proof_id: String,
    proof_revision: u64,
    template_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<HistoryOrigin>,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionHistory {
    // Legacy inline groups and newly appended groups remain pending until save.
    // Clones share their UUID bodies; normal persisted states carry only refs.
    pub groups: Vec<Arc<DecisionGroup>>,
    archives: Vec<HistoryArchiveRef>,
    origins: Vec<Option<HistoryOrigin>>,
}

impl DecisionHistory {
    pub fn record(
        &mut self,
        group: Arc<DecisionGroup>,
        workflow_id: &str,
        recording_run_id: &str,
        source_inventory_id: &str,
    ) {
        self.origins.resize(self.groups.len(), None);
        self.groups.push(group);
        self.origins.push(Some(HistoryOrigin {
            workflow_id: workflow_id.into(),
            recording_run_id: recording_run_id.into(),
            source_inventory_id: source_inventory_id.into(),
        }));
    }

    #[cfg(test)]
    pub fn push_group(&mut self, group: Arc<DecisionGroup>) {
        self.origins.resize(self.groups.len(), None);
        self.groups.push(group);
        self.origins.push(None);
    }

    pub fn occurrences(&self) -> u64 {
        self.archives
            .iter()
            .map(|entry| entry.occurrences)
            .sum::<u64>()
            + self
                .groups
                .iter()
                .map(|group| group.exchange_ids.len() as u64)
                .sum::<u64>()
    }

    pub fn group_count(&self) -> usize {
        self.archives.len() + self.groups.len()
    }

    pub fn has_inline_groups(&self) -> bool {
        !self.groups.is_empty()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn len(&self) -> usize {
        usize::try_from(self.occurrences()).unwrap()
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.origins.is_empty() || self.origins.len() == self.groups.len(),
            "ownership history origin count differs from its pending groups"
        );
        let mut proofs = BTreeMap::new();
        let mut occurrences = 0_u64;
        for entry in &self.archives {
            ensure!(
                valid_digest(&entry.sha256) && valid_digest(&entry.template_sha256),
                "invalid ownership history archive digest"
            );
            ensure!(
                entry.byte_length > 0
                    && entry.occurrences > 0
                    && !entry.archived_from_workflow.is_empty(),
                "invalid ownership history archive metadata"
            );
            validate_origin(entry.origin.as_ref())?;
            occurrences = occurrences
                .checked_add(entry.occurrences)
                .ok_or_else(|| anyhow::anyhow!("ownership history occurrence count overflow"))?;
            validate_proof(
                &mut proofs,
                &entry.proof_id,
                entry.proof_revision,
                &entry.template_sha256,
            )?;
        }
        for (index, group) in self.groups.iter().enumerate() {
            ensure!(
                !group.exchange_ids.is_empty(),
                "empty ownership history group"
            );
            validate_origin(self.origins.get(index).and_then(Option::as_ref))?;
            occurrences = occurrences
                .checked_add(group.exchange_ids.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("ownership history occurrence count overflow"))?;
            validate_proof(
                &mut proofs,
                &group.template.proof_id,
                group.template.proof_revision,
                &template_digest(&group.template)?,
            )?;
        }
        Ok(())
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_origin(origin: Option<&HistoryOrigin>) -> Result<()> {
    if let Some(origin) = origin {
        ensure!(
            !origin.workflow_id.is_empty()
                && !origin.recording_run_id.is_empty()
                && !origin.source_inventory_id.is_empty(),
            "empty ownership history origin"
        );
    }
    Ok(())
}

fn validate_proof(
    proofs: &mut BTreeMap<(String, u64), String>,
    id: &str,
    revision: u64,
    digest: &str,
) -> Result<()> {
    if let Some(previous) = proofs.insert((id.into(), revision), digest.into()) {
        ensure!(
            previous == digest,
            "contradictory historical ownership templates for one proof revision"
        );
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn template_digest(template: &DecisionTemplate) -> Result<String> {
    Ok(digest(&serde_json::to_vec(template)?))
}
