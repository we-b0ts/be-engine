//! Publish changed ownership memberships while retaining immutable unaffected scopes.
use crate::dependency::{
    attribution::DependencyOwner,
    observation::{RecordingManifest, SCOPE_SCHEMA, ScopeIndex, ScopeKind},
};
use crate::dependency_index::scoped;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

pub(super) fn freeze<'a>(
    root: &Path,
    manifest: &RecordingManifest,
    output: &Path,
    cases: impl Iterator<Item = &'a String>,
    decisions: &BTreeMap<Uuid, DependencyOwner>,
    digest: &str,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut scopes = Vec::new();
    for input in &manifest.inputs {
        scopes.push(root.join(&input.path).join(scoped::CASE_SCOPE));
    }
    for kind in ["startup", "process", "shutdown", "unattributed"] {
        scopes.push(root.join(format!("indexes/{kind}-scope.json")));
    }
    let mut originals = BTreeMap::new();
    let mut locations = BTreeMap::new();
    for path in scopes {
        if !path.is_file() {
            continue;
        }
        let index: ScopeIndex = serde_json::from_slice(&std::fs::read(&path)?)?;
        ensure!(
            index.schema == SCOPE_SCHEMA,
            "unsupported attribution scope schema"
        );
        ensure!(
            originals.insert(key(&index.scope), path).is_none(),
            "Source has duplicate ownership scope views"
        );
        for location in index.locations {
            ensure!(
                locations
                    .insert(location.offset, (index.scope.clone(), location))
                    .is_none(),
                "Source dependency occurs in multiple ownership views"
            );
        }
    }
    let mut changed = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let run_relpath = std::fs::canonicalize(root)?.to_string_lossy().to_string();
    let mut result: BTreeMap<String, ScopeIndex> = BTreeMap::new();
    for (_, (captured, location)) in locations {
        let captured_key = key(&captured);
        let scope = if let Some(owner) = decisions.get(&location.exchange_id) {
            seen.insert(location.exchange_id);
            match owner {
                DependencyOwner::Case { origin_case_id, .. } => ScopeKind::Case {
                    case_id: *origin_case_id,
                },
                DependencyOwner::Startup { .. } => ScopeKind::Startup,
                DependencyOwner::Process { .. } => ScopeKind::Process,
                DependencyOwner::Shutdown { .. } => ScopeKind::Shutdown,
                DependencyOwner::Unattributed { .. } => ScopeKind::Unattributed,
            }
        } else {
            captured
        };
        let effective_key = key(&scope);
        if effective_key != captured_key {
            changed.insert(captured_key);
            changed.insert(effective_key.clone());
        }
        result
            .entry(effective_key)
            .or_insert_with(|| ScopeIndex {
                schema: SCOPE_SCHEMA.into(),
                run_relpath: run_relpath.clone(),
                scope,
                locations: vec![],
            })
            .locations
            .push(location);
    }
    ensure!(
        seen.len() == decisions.len(),
        "attribution refers to absent Source dependency evidence"
    );
    let destination = output
        .join("dependency-scopes")
        .join(digest.trim_start_matches("sha256:"));
    crate::dependency_index::store::private_directory(&destination)?;
    let keys = cases.cloned().chain([
        "startup".into(),
        "process".into(),
        "shutdown".into(),
        "unattributed".into(),
    ]);
    let mut paths = BTreeMap::new();
    for key in keys {
        // Membership is the complete scope contract. Rewriting an unchanged
        // scope would change its file stamp and invalidate native index caches
        // on every attempt, even when only unrelated Case tails were attributed.
        if !changed.contains(&key)
            && let Some(original) = originals.get(&key)
        {
            paths.insert(key, original.clone());
            continue;
        }
        let scope = result.remove(&key).unwrap_or_else(|| ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: run_relpath.clone(),
            scope: match key.as_str() {
                "startup" => ScopeKind::Startup,
                "process" => ScopeKind::Process,
                "shutdown" => ScopeKind::Shutdown,
                "unattributed" => ScopeKind::Unattributed,
                _ => ScopeKind::Case {
                    case_id: key.parse().expect("manifest Case UUID"),
                },
            },
            locations: vec![],
        });
        let path = destination.join(format!("{key}-scope.json"));
        std::fs::write(&path, serde_json::to_vec(&scope)?)?;
        paths.insert(key, path);
    }
    Ok(paths)
}

fn key(scope: &ScopeKind) -> String {
    match scope {
        ScopeKind::Case { case_id } => case_id.to_string(),
        ScopeKind::Startup => "startup".into(),
        ScopeKind::Process => "process".into(),
        ScopeKind::Shutdown => "shutdown".into(),
        ScopeKind::Unattributed => "unattributed".into(),
    }
}
