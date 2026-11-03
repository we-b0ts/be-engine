//! Compose mechanical admission and explicitly declared Source ownership.
use crate::dependency::attribution::DependencyOwner;
use anyhow::Result;
use std::{collections::BTreeMap, path::Path};
use uuid::Uuid;

pub(super) struct Defaults {
    pub owners: BTreeMap<Uuid, DependencyOwner>,
    pub policy_identity: Option<String>,
    pub diagnostic: serde_json::Value,
}

pub(super) fn load(source: &Path, target: Option<&Path>) -> Result<Defaults> {
    let mut owners = super::case_defaults::load(source, target)?;
    let policy = super::policy_ownership::load(source, target)?;
    owners.extend(policy.owners);
    Ok(Defaults {
        owners,
        policy_identity: policy.policy_identity,
        diagnostic: policy.diagnostic,
    })
}

impl Defaults {
    pub(super) fn identity(&self) -> Result<String> {
        // Keep the established identity unchanged when no new contract exists.
        if let Some(policy) = &self.policy_identity {
            return Ok(crate::policy_evidence::digest(&serde_json::to_vec(&(
                "declared-source-ownership/v1",
                &self.owners,
                policy,
            ))?));
        }
        Ok(crate::policy_evidence::digest(&serde_json::to_vec(&(
            "case-default-admission/v1",
            &self.owners,
        ))?))
    }
}
