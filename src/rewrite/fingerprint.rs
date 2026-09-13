use std::path::Path;
use std::process::Command;
use std::{fs, io::Read as _};

use anyhow::{Context, Result, ensure};

mod engine;

const RUNTIME_PROGRESS_PATHSPECS: &[&str] = &[
    ":(exclude).traffic-e2e/progress.yaml",
    ":(exclude).traffic-e2e/replay-progress.yaml",
    ":(exclude).traffic-e2e/comparison-progress.yaml",
    ":(exclude).traffic-e2e/e2e-progress.yaml",
];

pub(super) fn repository_fingerprint(target_root: &Path) -> Result<String> {
    let mut hash = repository_files_hash(target_root)?;
    hash.update(b"startup-snapshot");
    hash.update(crate::startup::startup_snapshot_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    hash.update(b"target-environment");
    hash.update(crate::startup::startup_environment_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    Ok(hash.finish())
}

/// Portable delivery identity; private startup inputs belong to the canonical
/// validation context, not the candidate worktree's local runtime directory.
pub(super) fn code_fingerprint(target_root: &Path) -> Result<String> {
    Ok(repository_files_hash(target_root)?.finish())
}

fn repository_files_hash(target_root: &Path) -> Result<Fnv1a> {
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
/// files. Progress publication and private runtime are not code changes.
pub(super) fn matches_revision(target_root: &Path, revision: &str) -> Result<bool> {
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
    if !git_bytes(target_root, &diff)?.is_empty() {
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
    Ok(git_bytes(target_root, &untracked)?.is_empty())
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

pub(super) fn source_image_revision(target_root: &Path) -> Result<String> {
    crate::source_snapshot::source_image_revision(target_root)
}

pub(super) fn traffic_e2e_revision() -> Result<String> {
    engine::revision(&crate::engine_binary::executable()?)
}

pub(super) fn project_config_revision(target_root: &Path) -> Result<String> {
    config_file_revision(target_root, ".traffic-e2e/project.yaml", "project config")
}

pub(super) fn source_traffic_policy_revision(target_root: &Path) -> Result<String> {
    config_file_revision(
        target_root,
        ".traffic-e2e/source-traffic-policy.yaml",
        "source traffic policy",
    )
}

fn config_file_revision(target_root: &Path, relative: &str, label: &str) -> Result<String> {
    let path = target_root.join(relative);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read {label} {}", path.display()))?;
    let mut hash = Fnv1a::default();
    hash.update(&bytes);
    Ok(hash.finish())
}

pub(super) fn source_runtime_inputs_revision(target_root: &Path) -> Result<String> {
    let mut hash = Fnv1a::default();
    hash.update(crate::source_snapshot::source_runtime_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    hash.update(crate::startup::startup_snapshot_revision(target_root)?.as_bytes());
    hash.update(&[0]);
    Ok(hash.finish())
}

pub(super) fn id(parts: &[&str]) -> String {
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
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn ids_are_stable_and_framed() {
        assert_eq!(id(&["ab", "c"]), id(&["ab", "c"]));
        assert_ne!(id(&["ab", "c"]), id(&["a", "bc"]));
    }

    #[test]
    fn repository_fingerprint_ignores_runner_progress_but_tracks_policy_and_source() {
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir_all(repository.path().join(".traffic-e2e")).unwrap();
        fs::create_dir_all(repository.path().join("src")).unwrap();
        fs::write(
            repository.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(
            repository.path().join(".traffic-e2e/verification.yaml"),
            "version: 2\n",
        )
        .unwrap();
        for name in [
            "progress.yaml",
            "replay-progress.yaml",
            "comparison-progress.yaml",
            "e2e-progress.yaml",
        ] {
            fs::write(
                repository.path().join(".traffic-e2e").join(name),
                "attempt: 1\n",
            )
            .unwrap();
        }
        git_ok(repository.path(), &["init"]);
        git_ok(
            repository.path(),
            &["config", "user.email", "test@example.com"],
        );
        git_ok(
            repository.path(),
            &["config", "user.name", "Traffic E2E Test"],
        );
        git_ok(repository.path(), &["add", "."]);
        git_ok(repository.path(), &["commit", "-m", "baseline"]);

        let baseline = repository_fingerprint(repository.path()).unwrap();
        let regression = repository.path().join(crate::config::regression::PATH);
        fs::write(&regression, "require_comparison: false\n").unwrap();
        assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
        let code = code_fingerprint(repository.path()).unwrap();
        git_ok(repository.path(), &["add", crate::config::regression::PATH]);
        git_ok(
            repository.path(),
            &["commit", "-m", "track local regression policy"],
        );
        fs::write(
            &regression,
            "recording_run_id: \"20260911093000\"\nrequire_comparison: true\nskip: [GET /a]\n",
        )
        .unwrap();
        assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
        assert_eq!(code_fingerprint(repository.path()).unwrap(), code);
        fs::remove_file(&regression).unwrap();
        assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);
        for name in [
            "progress.yaml",
            "replay-progress.yaml",
            "comparison-progress.yaml",
            "e2e-progress.yaml",
        ] {
            fs::write(
                repository.path().join(".traffic-e2e").join(name),
                "attempt: 2\n",
            )
            .unwrap();
        }
        assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);

        let local_artifacts = repository.path().join(".traffic-e2e/local/artifacts");
        fs::create_dir_all(&local_artifacts).unwrap();
        fs::write(local_artifacts.join("runtime.jsonl"), "local evidence\n").unwrap();
        assert_eq!(repository_fingerprint(repository.path()).unwrap(), baseline);

        fs::write(
            repository.path().join(".traffic-e2e/verification.yaml"),
            "version: 2\nresponses: changed\n",
        )
        .unwrap();
        assert_ne!(repository_fingerprint(repository.path()).unwrap(), baseline);

        git_ok(
            repository.path(),
            &["checkout", "--", ".traffic-e2e/verification.yaml"],
        );
        fs::write(
            repository.path().join("src/lib.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )
        .unwrap();
        let dirty_source = repository_fingerprint(repository.path()).unwrap();
        assert_ne!(dirty_source, baseline);

        git_ok(repository.path(), &["add", "src/lib.rs"]);
        git_ok(repository.path(), &["commit", "-m", "change source"]);
        assert_eq!(
            repository_fingerprint(repository.path()).unwrap(),
            dirty_source
        );

        fs::write(
            repository.path().join("src/new.rs"),
            "pub const NEW: u8 = 1;\n",
        )
        .unwrap();
        let dirty_new_file = repository_fingerprint(repository.path()).unwrap();
        git_ok(repository.path(), &["add", "src/new.rs"]);
        git_ok(repository.path(), &["commit", "-m", "add source"]);
        assert_eq!(
            repository_fingerprint(repository.path()).unwrap(),
            dirty_new_file
        );

        fs::remove_file(repository.path().join("src/new.rs")).unwrap();
        let dirty_deletion = repository_fingerprint(repository.path()).unwrap();
        git_ok(repository.path(), &["add", "--update"]);
        git_ok(repository.path(), &["commit", "-m", "remove source"]);
        assert_eq!(
            repository_fingerprint(repository.path()).unwrap(),
            dirty_deletion
        );
    }

    fn git_ok(repository: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    }
}
