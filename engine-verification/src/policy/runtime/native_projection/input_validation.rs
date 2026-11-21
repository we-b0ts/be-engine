//! Immutable input verification retains signing-key witnesses for rule preflight.
mod input;
mod signed_input;
#[cfg(test)]
mod tests;
use super::*;
use crate::policy::{CompiledPolicy, NativeEffect};
use anyhow::ensure;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub struct SourceInputCase<'a> {
    pub id: &'a str,
    pub dir: &'a Path,
    pub request: &'a Value,
}
#[derive(Default)]
pub struct SourceInputValidation {
    pub rules: BTreeMap<String, usize>,
    pub key_witnesses: BTreeSet<(PathBuf, String)>,
}

pub fn validate_source_inputs(
    compiled: &CompiledPolicy,
    selected: &BTreeSet<String>,
    target_root: &Path,
    cases: &[SourceInputCase<'_>],
) -> Result<SourceInputValidation> {
    let mut checked = SourceInputValidation::default();
    let mut identities = BTreeSet::new();
    for case in cases {
        ensure!(
            identities.insert(case.id),
            "duplicate Source input Case identity"
        );
        input::validate(compiled, target_root, case, &mut checked)?;
        signed_input::validate(compiled, target_root, case, &mut checked)?;
    }
    for native in compiled
        .native
        .iter()
        .filter(|native| selected.contains(&native.rule.id))
    {
        if matches!(
            native.rule.effect,
            NativeEffect::InputJwt(_) | NativeEffect::InputSignedTimestamp(_)
        ) {
            ensure!(
                checked
                    .rules
                    .get(&native.rule.id)
                    .is_some_and(|count| *count > 0),
                "input rule {:?} has no complete positive Source evidence",
                native.rule.id
            );
        }
    }
    Ok(checked)
}
