use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

mod layout;

pub(super) use layout::{git_object_path, project_root_in_worktree};

const IGNORED_DIRECTORIES: &[&str] = &[".git", ".traffic-e2e", "node_modules", "target", "vendor"];
const NON_PRODUCTION_DIRECTORIES: &[&str] =
    &["benches", "examples", "fixtures", "testdata", "tests"];

pub(super) struct AddedLine {
    pub file: PathBuf,
    pub line: usize,
    pub text: String,
}

pub(super) struct AddedRustLines {
    pub merge_base: String,
    pub scanned_files: usize,
    pub files: Vec<PathBuf>,
    pub lines: Vec<AddedLine>,
}

#[cfg(test)]
pub(super) fn added_rust_lines(target_root: &Path, pr_base: &str) -> Result<AddedRustLines> {
    let base_ref = resolve_pr_base(target_root, pr_base)?;
    let merge_base = git_text(target_root, &["merge-base", "HEAD", &base_ref])?
        .trim()
        .to_string();
    changed_rust_lines(target_root, &merge_base)
}

pub(super) fn changed_rust_lines(target_root: &Path, base: &str) -> Result<AddedRustLines> {
    let merge_base = base.to_string();
    let mut files = BTreeSet::new();
    collect_changed_paths(
        target_root,
        &git_bytes(
            target_root,
            &[
                "diff",
                "--no-ext-diff",
                "--relative",
                "--name-only",
                "-z",
                "--diff-filter=ACMRT",
                &merge_base,
                "--",
                ".",
            ],
        )?,
        &mut files,
    )?;
    collect_changed_paths(
        target_root,
        &git_bytes(
            target_root,
            &[
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                ".",
            ],
        )?,
        &mut files,
    )?;
    let renamed_from = renamed_paths(target_root, &merge_base)?;

    let mut lines = Vec::new();
    for relative in &files {
        if is_tracked(target_root, relative)? {
            lines.extend(tracked_added_lines(
                target_root,
                &merge_base,
                relative,
                renamed_from.get(relative).map(PathBuf::as_path),
            )?);
        } else {
            lines.extend(untracked_added_lines(target_root, relative)?);
        }
    }
    Ok(AddedRustLines {
        merge_base,
        scanned_files: files.len(),
        files: files.into_iter().collect(),
        lines,
    })
}

fn renamed_paths(target_root: &Path, merge_base: &str) -> Result<BTreeMap<PathBuf, PathBuf>> {
    let raw = git_bytes(
        target_root,
        &[
            "diff",
            "--no-ext-diff",
            "--relative",
            "--name-status",
            "-z",
            "--find-renames",
            "--diff-filter=R",
            merge_base,
            "--",
            ".",
        ],
    )?;
    let fields = raw
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let (records, remainder) = fields.as_chunks::<3>();
    ensure!(
        remainder.is_empty(),
        "Git returned an incomplete rename record"
    );
    let mut renames = BTreeMap::new();
    for record in records {
        let status = std::str::from_utf8(record[0]).context("Git rename status is not UTF-8")?;
        ensure!(
            status.starts_with('R'),
            "unexpected Git rename status {status:?}"
        );
        let previous = PathBuf::from(
            std::str::from_utf8(record[1]).context("previous Git path is not UTF-8")?,
        );
        let current =
            PathBuf::from(std::str::from_utf8(record[2]).context("current Git path is not UTF-8")?);
        renames.insert(current, previous);
    }
    Ok(renames)
}

fn collect_changed_paths(
    target_root: &Path,
    raw: &[u8],
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for raw_path in raw.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let relative =
            std::str::from_utf8(raw_path).context("changed repository path is not UTF-8")?;
        let relative = PathBuf::from(relative);
        if !is_scanned_rust_path(&relative) {
            continue;
        }
        let path = target_root.join(&relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect changed source {path:?}"));
            }
        };
        if metadata.is_file() && !metadata.file_type().is_symlink() {
            files.insert(relative);
        }
    }
    Ok(())
}

fn is_scanned_rust_path(path: &Path) -> bool {
    is_safe_relative_rust_path(path)
        && !path.components().any(|component| {
            let Component::Normal(component) = component else {
                return true;
            };
            IGNORED_DIRECTORIES.contains(&component.to_string_lossy().as_ref())
        })
}

pub(super) fn is_production_rust_path(path: &Path) -> bool {
    path.components().any(
        |component| matches!(component, Component::Normal(value) if value == "src"),
    ) && !path.components().any(|component| {
        matches!(component, Component::Normal(value) if NON_PRODUCTION_DIRECTORIES.contains(&value.to_string_lossy().as_ref()))
    })
}

pub(super) fn is_safe_relative_rust_path(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
        && !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_tracked(target_root: &Path, relative: &Path) -> Result<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(relative)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to inspect Git tracking state for {relative:?}"))?;
    Ok(status.success())
}

fn tracked_added_lines(
    target_root: &Path,
    merge_base: &str,
    relative: &Path,
    previous: Option<&Path>,
) -> Result<Vec<AddedLine>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args([
            "diff",
            "--no-ext-diff",
            "--no-color",
            "--unified=0",
            "--find-renames",
            merge_base,
            "--",
        ])
        .args(previous)
        .arg(relative)
        .output()
        .with_context(|| format!("failed to inspect added lines for {relative:?}"))?;
    ensure!(
        output.status.success(),
        "Git failed while inspecting added lines for {relative:?}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    parse_added_lines(relative, &output.stdout)
}

fn parse_added_lines(relative: &Path, diff: &[u8]) -> Result<Vec<AddedLine>> {
    let mut lines = Vec::new();
    let mut new_line = None;
    for raw_line in diff.split(|byte| *byte == b'\n') {
        if raw_line.starts_with(b"@@ ") {
            new_line = Some(parse_new_hunk_start(raw_line)?);
            continue;
        }
        let Some(line_number) = new_line else {
            continue;
        };
        match raw_line.first().copied() {
            Some(b'+') => {
                let text = std::str::from_utf8(&raw_line[1..])
                    .with_context(|| {
                        format!("added Rust source line in {relative:?} is not UTF-8")
                    })?
                    .trim_end_matches('\r')
                    .to_string();
                lines.push(AddedLine {
                    file: relative.to_path_buf(),
                    line: line_number,
                    text,
                });
                new_line = Some(line_number + 1);
            }
            Some(b'-') | Some(b'\\') => {}
            Some(b' ') => new_line = Some(line_number + 1),
            _ => new_line = None,
        }
    }
    Ok(lines)
}

fn parse_new_hunk_start(raw_header: &[u8]) -> Result<usize> {
    let header = std::str::from_utf8(raw_header).context("Git diff hunk header is not UTF-8")?;
    let range = header
        .split_ascii_whitespace()
        .find_map(|part| part.strip_prefix('+'))
        .context("Git diff hunk header has no new-file range")?;
    range
        .split(',')
        .next()
        .context("Git diff hunk header has an empty new-file range")?
        .parse::<usize>()
        .context("Git diff hunk header has an invalid new-file line")
}

fn untracked_added_lines(target_root: &Path, relative: &Path) -> Result<Vec<AddedLine>> {
    let source = fs::read_to_string(target_root.join(relative))
        .with_context(|| format!("failed to read untracked Rust source {relative:?}"))?;
    Ok(source
        .lines()
        .enumerate()
        .map(|(index, text)| AddedLine {
            file: relative.to_path_buf(),
            line: index + 1,
            text: text.to_string(),
        })
        .collect())
}

pub(super) fn resolve_pr_base(target_root: &Path, pr_base: &str) -> Result<String> {
    for candidate in [
        format!("refs/heads/{pr_base}"),
        format!("refs/remotes/origin/{pr_base}"),
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(target_root)
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("{candidate}^{{commit}}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("failed to resolve pull-request base {candidate:?}"))?;
        if status.success() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "pr_base {pr_base:?} does not exist as a local branch or origin remote-tracking branch"
    )
}

pub(super) fn git_text(target_root: &Path, args: &[&str]) -> Result<String> {
    let raw = git_bytes(target_root, args)?;
    String::from_utf8(raw).context("Git output is not UTF-8")
}

pub(super) fn git_bytes(target_root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(args)
        .output()
        .context("failed to inspect changed target files with Git")?;
    ensure!(
        output.status.success(),
        "Git command failed while inspecting changed target files: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}
