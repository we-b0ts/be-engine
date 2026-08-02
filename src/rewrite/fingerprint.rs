use std::path::Path;
use std::process::Command;
use std::{fs, io::Read as _};

use anyhow::{Context, Result, ensure};

const RUNTIME_PROGRESS_PATHSPECS: &[&str] = &[
    ":(exclude).traffic-e2e/replay-progress.yaml",
    ":(exclude).traffic-e2e/comparison-progress.yaml",
    ":(exclude).traffic-e2e/e2e-progress.yaml",
];
const MAX_RUNTIME_INPUT_FILES: usize = 4_096;
const MAX_RUNTIME_INPUT_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn repository_fingerprint(target_root: &Path) -> Result<String> {
    let head = git(target_root, &["rev-parse", "HEAD"])?;
    let mut diff_args = vec![
        "diff",
        "--binary",
        "HEAD",
        "--",
        ".",
        ":(exclude).traffic-e2e/local/**",
        ":(exclude).traffic-e2e/artifacts/**",
        ":(exclude).traffic-e2e/data/**",
    ];
    diff_args.extend_from_slice(RUNTIME_PROGRESS_PATHSPECS);
    let diff = git_bytes(target_root, &diff_args)?;
    let mut untracked_args = vec![
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        ".",
        ":(exclude).traffic-e2e/local/**",
        ":(exclude).traffic-e2e/artifacts/**",
        ":(exclude).traffic-e2e/data/**",
    ];
    untracked_args.extend_from_slice(RUNTIME_PROGRESS_PATHSPECS);
    let untracked = git_bytes(target_root, &untracked_args)?;
    let mut hash = Fnv1a::default();
    hash.update(head.trim().as_bytes());
    hash.update(&diff);
    for relative in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        hash.update(relative);
        let relative = std::str::from_utf8(relative).context("untracked path is not UTF-8")?;
        let path = target_root.join(relative);
        if path.is_file() {
            hash.update(&std::fs::read(&path).with_context(|| {
                format!("failed to fingerprint untracked file {}", path.display())
            })?);
        }
    }
    Ok(hash.finish())
}

pub(super) fn source_container_revision(container: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(["container", "inspect", "--format", "{{.Image}}", container])
        .output()
        .with_context(|| format!("failed to inspect source container {container:?}"))?;
    ensure!(
        output.status.success(),
        "failed to resolve immutable source image for {container:?}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let revision = String::from_utf8(output.stdout)
        .context("source image identity is not UTF-8")?
        .trim()
        .to_string();
    ensure!(
        !revision.is_empty(),
        "source container has no image identity"
    );
    Ok(revision)
}

pub(super) fn traffic_e2e_revision() -> Result<String> {
    let executable = std::env::current_exe().context("failed to resolve traffic-e2e binary")?;
    let mut file = fs::File::open(&executable)
        .with_context(|| format!("failed to read traffic-e2e binary {}", executable.display()))?;
    let mut hash = Fnv1a::default();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).with_context(|| {
            format!(
                "failed to fingerprint traffic-e2e binary {}",
                executable.display()
            )
        })?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finish())
}

pub(super) fn source_runtime_inputs_revision(
    target_root: &Path,
    source_container: &str,
) -> Result<String> {
    let source_revision = source_container_revision(source_container)?;
    let mut hash = Fnv1a::default();
    hash.update(source_revision.as_bytes());
    hash.update(&[0]);
    let boot = target_root.join(".traffic-e2e/boot");
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    hash_runtime_input_path(&boot, &boot, &mut hash, &mut files, &mut bytes)?;
    Ok(hash.finish())
}

fn hash_runtime_input_path(
    root: &Path,
    path: &Path,
    hash: &mut Fnv1a,
    files: &mut usize,
    bytes: &mut u64,
) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && path == root => {
            hash.update(b"boot:absent");
            return Ok(());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect runtime input {}", path.display()));
        }
    };
    let relative = path.strip_prefix(root).unwrap_or(path);
    hash.update(relative.as_os_str().as_encoded_bytes());
    hash.update(&[0]);
    if metadata.file_type().is_symlink() {
        hash.update(b"symlink");
        hash.update(fs::read_link(path)?.as_os_str().as_encoded_bytes());
        hash.update(&[0]);
        return Ok(());
    }
    if metadata.is_dir() {
        hash.update(b"directory");
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("failed to read runtime input directory {}", path.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            hash_runtime_input_path(root, &entry.path(), hash, files, bytes)?;
        }
        return Ok(());
    }
    ensure!(
        metadata.is_file(),
        "runtime input is neither a file, directory, nor symlink: {}",
        path.display()
    );
    *files = files.saturating_add(1);
    *bytes = bytes.saturating_add(metadata.len());
    ensure!(
        *files <= MAX_RUNTIME_INPUT_FILES && *bytes <= MAX_RUNTIME_INPUT_BYTES,
        "runtime inputs exceed the bounded fingerprint budget"
    );
    hash.update(b"file");
    hash.update(&metadata.len().to_le_bytes());
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to read runtime input {}", path.display()))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash runtime input {}", path.display()))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    hash.update(&[0]);
    Ok(())
}

pub(super) fn id(parts: &[&str]) -> String {
    let mut hash = Fnv1a::default();
    for part in parts {
        hash.update(part.as_bytes());
        hash.update(&[0]);
    }
    hash.finish()
}

fn git(target_root: &Path, args: &[&str]) -> Result<String> {
    let bytes = git_bytes(target_root, args)?;
    String::from_utf8(bytes).context("git output is not UTF-8")
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
        for name in [
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
        assert_ne!(repository_fingerprint(repository.path()).unwrap(), baseline);
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
