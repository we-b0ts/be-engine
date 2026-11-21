//! Materialize native indexes for changed ownership before the next Replay.
use super::views::{GLOBAL_SCOPES, freeze_scopes};
use crate::dependency_index::{global, recording, store};
use anyhow::Result;
use std::{collections::BTreeSet, path::Path};

pub fn prewarm_attribution_indexes(
    target: &Path,
    source: &Path,
    changed: &BTreeSet<String>,
    validate: impl Fn(&serde_json::Value) -> Result<()>,
) -> Result<()> {
    let selected = changed
        .iter()
        .map(String::as_str)
        .filter(|&scope| scope != "shutdown");
    if selected.clone().next().is_none() {
        return Ok(());
    }
    let (root, manifest) = recording::manifest(source)?;
    recording::authenticate(&root)?;
    let (owners, digest) =
        crate::coordination::freeze_dependency_attribution(Some(target), &root, &manifest.run_id)?;
    let cache = store::cache_directory(&root);
    store::private_directory(&cache)?;
    let stage = cache.join(format!(".attribution-{}", uuid::Uuid::new_v4().simple()));
    store::private_directory(&stage)?;
    let result = (|| -> Result<()> {
        let paths = freeze_scopes(&root, &manifest, &stage, selected, &owners, &digest)?;
        for (scope, path) in paths {
            if GLOBAL_SCOPES.contains(&scope.as_str()) {
                global::load_global_index(&path, |value| validate(value))?;
            } else {
                crate::dependency_index::load_file(&path)?;
            }
        }
        Ok(())
    })();
    let cleanup = std::fs::remove_dir_all(stage);
    result?;
    cleanup?;
    Ok(())
}
