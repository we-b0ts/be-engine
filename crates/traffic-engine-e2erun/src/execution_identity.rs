//! Identities of repository code, startup inputs and actual execution policy.
use std::path::Path;
use std::process::Command;
use std::{fs, io::Read as _};

use anyhow::{Context, Result, ensure};

mod cache;
mod engine;

pub use crate::config::project_policy_path as policy_file;

const RUNTIME_PROGRESS_PATHSPECS: &[&str] = &[
    ":(exclude).traffic-e2e/progress.yaml",
    ":(exclude).traffic-e2e/replay-progress.yaml",
    ":(exclude).traffic-e2e/e2e-progress.yaml",
];

pub fn repository_fingerprint(target_root: &Path) -> Result<String> {
    if let Some(fingerprint) = cache::repository(target_root) {
        return Ok(fingerprint);
    }
    let hash = repository_files_hash(target_root, false)?;
    let fingerprint = runtime_inputs_fingerprint(target_root, hash)?;
    cache::insert_repository(target_root.to_path_buf(), fingerprint.clone());
    Ok(fingerprint)
}

/// Review identity excludes traffic policy, while verification retains it.
pub fn review_fingerprint(target_root: &Path) -> Result<String> {
    runtime_inputs_fingerprint(target_root, repository_files_hash(target_root, true)?)
}

/// Identity of executed behavior. Only process-owned traffic classification may
/// change when reusing responses from a finalized Replay.
pub fn replay_identity(target_root: &Path) -> Result<String> {
    let mut hash = Fnv1a::default();
    hash.update(b"rewrite-replay-identity-v1");
    hash.update(review_fingerprint(target_root)?.as_bytes());
    let regression = crate::config::regression::RegressionScope::load(target_root)?;
    if let Some(timing) = regression.replay_timing {
        hash.update(b"regression-replay-timing-v1");
        hash.update(&serde_json::to_vec(&timing)?);
        if timing == crate::replay::ReplayStreamTiming::Fast {
            hash.update(&regression.replay_interval_cap_ms.to_le_bytes());
        }
    }
    let policy = policy_file(target_root)?;
    match fs::read(&policy) {
        Ok(bytes) => {
            let compiled = crate::policy::parse_and_compile_policy(std::str::from_utf8(&bytes)?)?;
            hash.update(b"runtime-policy-effects-v1");
            hash.update(compiled.fingerprints.runtime.as_bytes());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hash.update(b"no-verification-policy")
        }
        Err(error) => {
            return Err(error).context("failed to fingerprint Replay verification policy");
        }
    }
    Ok(hash.finish())
}

fn runtime_inputs_fingerprint(target_root: &Path, mut hash: Fnv1a) -> Result<String> {
    hash.update(b"startup-snapshot");
    hash.update(crate::startup::startup_snapshot_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    hash.update(b"target-environment");
    hash.update(crate::startup::startup_environment_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    Ok(hash.finish())
}

pub fn startup_inputs_fingerprint(target_root: &Path) -> Result<String> {
    runtime_inputs_fingerprint(target_root, Fnv1a::default())
}

/// Portable delivery identity; private startup inputs belong to the canonical
/// validation context, not the candidate worktree's local runtime directory.
pub fn code_fingerprint(target_root: &Path) -> Result<String> {
    Ok(repository_files_hash(target_root, true)?.finish())
}

fn repository_files_hash(target_root: &Path, review: bool) -> Result<Fnv1a> {
    if let Some(hash) = cache::repository_files(target_root, review) {
        return Ok(hash);
    }
    let policy = policy_file(target_root)?;
    let managed = crate::e2e_run::resolve_managed_directories(target_root)?;
    if managed.len() == 1 {
        let hash = directory_files_hash(&managed[0].root, review, &policy)?;
        cache::insert_repository_files(target_root.to_path_buf(), review, hash);
        return Ok(hash);
    }
    let mut hash = Fnv1a::default();
    for directory in managed {
        hash.update(b"managed-directory");
        hash.update(directory.target_relative.as_os_str().as_encoded_bytes());
        hash.update(&[0]);
        hash.update(
            directory_files_hash(&directory.root, review, &policy)?
                .finish()
                .as_bytes(),
        );
        hash.update(&[0]);
    }
    cache::insert_repository_files(target_root.to_path_buf(), review, hash);
    Ok(hash)
}

pub fn with_repository_cache<T>(operation: impl FnOnce() -> T) -> T {
    cache::scope(operation)
}

pub fn fresh_replay_identity(root: &Path) -> Result<String> {
    cache::fresh(|| replay_identity(root))
}

fn directory_files_hash(target_root: &Path, review: bool, policy: &Path) -> Result<Fnv1a> {
    let mut paths_args = vec![
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        ".",
        crate::internal_runtime::LOCAL_GIT_PATHSPEC,
    ];
    paths_args.extend_from_slice(RUNTIME_PROGRESS_PATHSPECS);
    paths_args.push(crate::config::regression::GIT_PATHSPEC);
    let listed = git_bytes(target_root, &paths_args)?;
    let mut paths = listed
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .filter(|path| {
            !review
                || std::str::from_utf8(path)
                    .is_ok_and(|relative| target_root.join(relative) != policy)
        })
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();
    let mut hash = Fnv1a::default();
    for relative in paths {
        let relative = std::str::from_utf8(relative).context("repository path is not UTF-8")?;
        hash_repository_path(target_root, relative, &mut hash)?;
    }
    Ok(hash)
}

/// Compare a purpose's committed baseline with the current tracked and untracked
/// files. Traffic policy, progress publication and private runtime are not code changes.
pub fn matches_revision(target_root: &Path, revision: &str) -> Result<bool> {
    if let Some(matches) = cache::revision_matches(target_root, revision) {
        return Ok(matches);
    }
    let policy = policy_file(target_root)?;
    let mut matches = true;
    for directory in crate::e2e_run::resolve_managed_directories(target_root)? {
        if !directory_matches_revision(&directory.root, revision, &policy)? {
            matches = false;
            break;
        }
    }
    cache::insert_revision_matches(target_root.to_path_buf(), revision.to_owned(), matches);
    Ok(matches)
}

fn directory_matches_revision(target_root: &Path, revision: &str, policy: &Path) -> Result<bool> {
    let mut diff = vec![
        "diff",
        "--no-ext-diff",
        "--ignore-submodules=none",
        "--name-only",
        "-z",
        revision,
        "--",
        ".",
        crate::internal_runtime::LOCAL_GIT_PATHSPEC,
        crate::config::regression::GIT_PATHSPEC,
    ];
    diff.extend_from_slice(RUNTIME_PROGRESS_PATHSPECS);
    if git_bytes(target_root, &diff)?
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .any(|p| {
            std::str::from_utf8(p).map_or(true, |relative| target_root.join(relative) != policy)
        })
    {
        return Ok(false);
    }
    let mut untracked = vec![
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        ".",
        crate::internal_runtime::LOCAL_GIT_PATHSPEC,
        crate::config::regression::GIT_PATHSPEC,
    ];
    untracked.extend_from_slice(RUNTIME_PROGRESS_PATHSPECS);
    Ok(!git_bytes(target_root, &untracked)?
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .any(|p| {
            std::str::from_utf8(p).map_or(true, |relative| target_root.join(relative) != policy)
        }))
}

fn hash_repository_path(target_root: &Path, relative: &str, hash: &mut Fnv1a) -> Result<()> {
    let path = target_root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect repository path {}", path.display()));
        }
    };
    hash.update(relative.as_bytes());
    hash.update(&[0]);
    if metadata.file_type().is_symlink() {
        hash.update(b"symlink");
        hash.update(fs::read_link(&path)?.as_os_str().as_encoded_bytes());
        hash.update(&[0]);
        return Ok(());
    }
    if metadata.is_dir() {
        if path.join(".git").exists() {
            hash.update(b"repository");
            hash.update(repository_fingerprint(&path)?.as_bytes());
        } else {
            hash.update(b"uninitialized-repository");
            hash.update(&git_bytes(
                target_root,
                &["ls-files", "--stage", "--", relative],
            )?);
        }
        hash.update(&[0]);
        return Ok(());
    }
    ensure!(
        metadata.is_file(),
        "repository entry is neither a file, directory, nor symlink: {}",
        path.display()
    );
    hash.update(b"file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        hash.update(&(metadata.permissions().mode() & 0o111).to_le_bytes());
    }
    hash.update(&metadata.len().to_le_bytes());
    let mut file = fs::File::open(&path)
        .with_context(|| format!("failed to read repository path {}", path.display()))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash repository path {}", path.display()))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    hash.update(&[0]);
    Ok(())
}

pub fn source_image_revision(target_root: &Path) -> Result<String> {
    crate::source_snapshot::source_image_revision(target_root)
}

pub fn traffic_e2e_revision() -> Result<String> {
    engine::revision(&crate::engine_binary::executable()?)
}

pub fn project_config_revision(target_root: &Path) -> Result<String> {
    config_file_revision(target_root, ".traffic-e2e/project.yaml", "project config")
}

pub fn source_traffic_policy_revision(target_root: &Path) -> Result<String> {
    let path = policy_file(target_root)?;
    let source = fs::read_to_string(&path)
        .with_context(|| format!("failed to read traffic policy {}", path.display()))?;
    Ok(crate::policy::parse_and_compile_policy(&source)?
        .fingerprints
        .capture)
}

fn config_file_revision(target_root: &Path, relative: &str, label: &str) -> Result<String> {
    let path = target_root.join(relative);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    let mut hash = Fnv1a::default();
    hash.update(&bytes);
    Ok(hash.finish())
}

pub fn source_runtime_inputs_revision(target_root: &Path) -> Result<String> {
    let mut hash = Fnv1a::default();
    hash.update(crate::source_snapshot::source_runtime_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    hash.update(crate::startup::startup_snapshot_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    Ok(hash.finish())
}

pub fn id(parts: &[&str]) -> String {
    let mut hash = Fnv1a::default();
    for part in parts {
        hash.update(part.as_bytes());
        hash.update(&[0]);
    }
    hash.finish()
}

fn git_bytes(target_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(args)
        .output()
        .context("failed to run git for rewrite fingerprint")?;
    ensure!(
        output.status.success(),
        "git rewrite fingerprint command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

#[derive(Clone, Copy)]
struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Self(0xcbf29ce484222325)
    }
}

impl Fnv1a {
    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(self) -> String {
        format!("fnv1a64:{:016x}", self.0)
    }
}

#[cfg(test)]
mod tests;
