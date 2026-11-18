//! Cargo and toolchain input identity, including configuration inherited from
//! repository ancestors outside the target's managed delivery directories.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::fingerprint;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use traffic_rewrite_model::rewrite::model::{RewriteApiStatus, RewriteState};

const FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config",
    ".cargo/config.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
];

fn paths(root: &Path) -> Result<(PathBuf, BTreeSet<PathBuf>)> {
    let repository = crate::repository::git_root(root)?;
    let mut paths = BTreeSet::new();
    for directory in crate::e2e_run::resolve_managed_directories(root)? {
        let mut current = Some(directory.root.as_path());
        while let Some(parent) = current.filter(|path| path.starts_with(&repository)) {
            paths.extend(FILES.iter().map(|name| parent.join(name)));
            current = parent.parent();
        }
    }
    Ok((repository, paths))
}

pub fn fingerprint(root: &Path) -> Result<String> {
    let (repository, paths) = paths(root)?;
    let mut digest = Sha256::new();
    digest.update(b"final-build-inputs-v1");
    for path in paths {
        let relative = path.strip_prefix(&repository)?;
        let name = relative.as_os_str().as_encoded_bytes();
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name);
        match fs::read(&path) {
            Ok(bytes) => {
                digest.update([1]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => digest.update([0]),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read final check input {}", path.display()));
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn ensure_committed(root: &Path) -> Result<()> {
    let (repository, paths) = paths(root)?;
    let mut arguments = vec!["diff", "--no-ext-diff", "--name-only", "HEAD", "--"];
    let names = paths
        .iter()
        .map(|path| {
            path.strip_prefix(&repository)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    arguments.extend(names.iter().map(String::as_str));
    ensure!(
        crate::source_diff::git_text(&repository, &arguments)?
            .trim()
            .is_empty(),
        "commit changed Cargo and toolchain inputs before final review or admission"
    );
    Ok(())
}

pub fn context(root: &Path, state: &RewriteState) -> Result<String> {
    let mut inventory = state
        .api_inventory
        .iter()
        .map(|item| -> Result<_> {
            // A legacy inventory adopts its recorded canonical pattern on first
            // activation. Bind that effective route so adoption is not a scope edit.
            let source_route = match item
                .source_route
                .as_ref()
                .or_else(|| state.source_route_bindings.get(&item.api))
            {
                Some(route) => route.clone(),
                None => item
                    .api
                    .parse::<traffic_engine::RecordingApi>()?
                    .path_pattern()
                    .to_string(),
            };
            Ok((
                &item.api,
                source_route,
                item.status == RewriteApiStatus::Skipped,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    inventory.sort_by(|left, right| left.0.cmp(right.0));
    let policy = fingerprint::policy_file(root)?;
    let policy = match fs::read_to_string(policy) {
        Ok(policy) => policy,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).context("failed to read final regression policy"),
    };
    Ok(fingerprint::id(&[
        "pre-revalidation-context-v2",
        &crate::e2e_run::resolve_project(root)?.1.quality_check,
        &state.workflow_id,
        &state.recording_run_id,
        &serde_json::to_string(&inventory)?,
        &policy,
    ]))
}
pub fn ensure_candidate_committed(root: &Path) -> Result<()> {
    ensure_committed(root)?;
    ensure!(
        fingerprint::matches_revision(root, "HEAD")?,
        "commit the final candidate's target and managed code before review check --pre-revalidation or final admission"
    );
    Ok(())
}
