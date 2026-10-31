//! Shared ownership proofs with complete finite occurrence membership.
//!
//! The public per-occurrence DTO remains a projection. Workflow state keeps one
//! immutable template per proof group so status does not allocate or clone that
//! proof once for every notification in a large Source run.
mod serde;
mod snapshot;
#[cfg(test)]
mod tests;

use crate::dependency::attribution::{AttributionDecision, AttributionProof, DependencyOwner};
use ::serde::{Deserialize, Serialize};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
#[cfg(test)]
std::thread_local! {
    static DTO_PROJECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::rewrite::dependency_review) struct DecisionTemplate {
    pub owner: DependencyOwner,
    pub proof_id: String,
    pub proof_revision: u64,
    pub proof: AttributionProof,
    pub rule_bindings: BTreeMap<String, String>,
}

impl DecisionTemplate {
    pub(super) fn from_decision(decision: AttributionDecision) -> Self {
        Self {
            owner: decision.owner,
            proof_id: decision.proof_id,
            proof_revision: decision.proof_revision,
            proof: decision.proof,
            rule_bindings: decision.rule_bindings,
        }
    }
    pub(super) fn decision(&self, exchange_id: Uuid) -> AttributionDecision {
        #[cfg(test)]
        DTO_PROJECTIONS.with(|count| count.set(count.get() + 1));
        AttributionDecision {
            exchange_id,
            owner: self.owner.clone(),
            proof_id: self.proof_id.clone(),
            proof_revision: self.proof_revision,
            proof: self.proof.clone(),
            rule_bindings: self.rule_bindings.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionGroup {
    pub template: DecisionTemplate,
    /// Active groups are sorted sets. History retains the original occurrence
    /// order, including separate repeated decisions across proof revisions.
    pub exchange_ids: Vec<Uuid>,
}

impl DecisionGroup {
    pub(super) fn contains(&self, id: &Uuid) -> bool {
        self.exchange_ids.binary_search(id).is_ok()
    }
    pub(super) fn validate_active(&self) -> Result<()> {
        ensure!(
            !self.exchange_ids.is_empty(),
            "ownership group has no Source occurrences"
        );
        ensure!(
            self.exchange_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "ownership group contains repeated or unordered Source identities"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(in crate::rewrite) struct DecisionSet {
    groups: Vec<Arc<DecisionGroup>>,
}

impl DecisionSet {
    pub(in crate::rewrite) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
    #[cfg(test)]
    pub(in crate::rewrite) fn len(&self) -> usize {
        self.groups
            .iter()
            .map(|group| group.exchange_ids.len())
            .sum()
    }
    pub(super) fn get(&self, id: &Uuid) -> Option<&DecisionTemplate> {
        self.groups
            .iter()
            .find(|group| group.contains(id))
            .map(|group| &group.template)
    }
    pub(super) fn contains_key(&self, id: &Uuid) -> bool {
        self.get(id).is_some()
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Uuid, &DecisionTemplate)> {
        self.groups.iter().flat_map(|group| {
            group
                .exchange_ids
                .iter()
                .map(move |id| (id, &group.template))
        })
    }
    pub(super) fn templates(&self) -> impl Iterator<Item = &DecisionTemplate> {
        self.groups.iter().map(|group| &group.template)
    }
    pub(super) fn retain_groups(
        &mut self,
        mut keep: impl FnMut(&DecisionTemplate) -> bool,
    ) -> Vec<Arc<DecisionGroup>> {
        let mut removed = vec![];
        self.groups.retain(|group| {
            if keep(&group.template) {
                true
            } else {
                removed.push(group.clone());
                false
            }
        });
        removed
    }
    pub(super) fn insert_group(&mut self, group: Arc<DecisionGroup>) -> Result<()> {
        group.validate_active()?;
        for previous in &mut self.groups {
            if previous.exchange_ids == group.exchange_ids {
                // Replace the whole immutable group without cloning its UUIDs.
                previous.clone_from(&group);
                return Ok(());
            }
        }
        let mut retained = Vec::with_capacity(self.groups.len() + 1);
        for previous in self.groups.drain(..) {
            if !previous.exchange_ids.iter().any(|id| group.contains(id)) {
                retained.push(previous);
                continue;
            }
            let exchange_ids = previous
                .exchange_ids
                .iter()
                .filter(|id| !group.contains(id))
                .copied()
                .collect::<Vec<_>>();
            if !exchange_ids.is_empty() {
                retained.push(Arc::new(DecisionGroup {
                    template: previous.template.clone(),
                    exchange_ids,
                }));
            }
        }
        retained.push(group);
        self.groups = retained;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(in crate::rewrite) struct DecisionHistory {
    groups: Vec<Arc<DecisionGroup>>,
}

impl DecisionHistory {
    #[cfg(test)]
    pub(in crate::rewrite) fn len(&self) -> usize {
        self.groups
            .iter()
            .map(|group| group.exchange_ids.len())
            .sum()
    }
    pub(super) fn push_group(&mut self, group: Arc<DecisionGroup>) {
        self.groups.push(group);
    }
}
