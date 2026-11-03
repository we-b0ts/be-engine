//! Async ownership has local plan evidence and a separate runtime declaration.
use anyhow::{Context, Result};
use std::collections::BTreeMap;

use crate::policy::AsyncApiRules;

pub(super) fn expand(
    mut rules: Option<BTreeMap<String, AsyncApiRules>>,
    revision: Option<&str>,
) -> Result<Option<BTreeMap<String, AsyncApiRules>>> {
    if let Some(rules) = &mut rules {
        for scenarios in rules.values_mut() {
            for rule in &mut scenarios.0 {
                if let Some(ownership) = &mut rule.ownership
                    && let Some(local) = &ownership.proof
                {
                    ownership.proof = Some(serde_yaml::from_value(super::proof::expand(
                        Some(serde_yaml::to_value(local)?),
                        None,
                        revision,
                    )?)?);
                }
            }
        }
    }
    Ok(rules)
}

pub(super) fn require(rules: Option<&BTreeMap<String, AsyncApiRules>>) -> Result<()> {
    for scenarios in rules.into_iter().flat_map(BTreeMap::values) {
        for rule in scenarios.iter() {
            if let Some(ownership) = &rule.ownership {
                ownership
                    .proof
                    .as_ref()
                    .context("async ownership planning requires local Source proof")?
                    .validate(false)?;
            }
        }
    }
    Ok(())
}
