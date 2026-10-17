//! Cargo and toolchain input identity, including configuration inherited from
//! repository ancestors outside the target's managed delivery directories.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

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

pub(super) fn fingerprint(root: &Path) -> Result<String> {
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

pub(super) fn ensure_committed(root: &Path) -> Result<()> {
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
        super::source_diff::git_text(&repository, &arguments)?
            .trim()
            .is_empty(),
        "commit changed Cargo and toolchain inputs before final review or admission"
    );
    Ok(())
}
