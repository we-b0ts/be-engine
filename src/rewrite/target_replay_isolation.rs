use crate::rewrite::source_diff::{
    AddedLine, AddedRustLines, changed_rust_lines, git_text, is_production_rust_path,
    is_safe_target_relative_rust_path,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub(super) const GATE_NAME: &str = "replay-isolation";
pub(super) const GATE_VERSION: &str = "replay-isolation-v6";

const MAX_REPORTED_VIOLATIONS: usize = 64;
const SOURCE_EVIDENCE_TRAILER: &str = "Hardcode-Source-Evidence:";

const NON_PRODUCTION_SOURCE_DIRECTORIES: &[&str] = &[
    "benches", "example", "examples", "fixture", "fixtures", "test", "testdata", "tests",
];
const PRODUCTION_SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "clj", "cpp", "cs", "cxx", "ex", "exs", "go", "groovy", "h", "hh", "hpp", "hxx",
    "java", "js", "jsx", "kt", "kts", "m", "mm", "php", "py", "rb", "rs", "scala", "sh", "swift",
    "ts", "tsx",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayIsolationReport {
    schema_version: u8,
    gate: String,
    status: ReplayIsolationStatus,
    scanned_files: usize,
    scanned_added_lines: usize,
    violations: Vec<ReplayIsolationViolation>,
    omitted_violations: usize,
}

impl ReplayIsolationReport {
    pub(super) fn passed(&self) -> bool {
        self.schema_version == 2
            && self.gate == GATE_NAME
            && matches!(self.status, ReplayIsolationStatus::Passed)
            && self.violations.is_empty()
            && self.omitted_violations == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReplayIsolationStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct ReplayIsolationViolation {
    file: PathBuf,
    line: usize,
    column: usize,
    rule: String,
    matched: String,
    reason: String,
    required_change: String,
}

#[derive(Clone, Copy)]
struct ForbiddenMarker {
    rule: &'static str,
    marker: &'static str,
    reason: &'static str,
    required_change: &'static str,
}

const ALL_RUST_FORBIDDEN_MARKERS: &[ForbiddenMarker] = &[ForbiddenMarker {
    rule: "replay_hostname",
    marker: ".trp.test",
    reason: "code depends on a replay-only synthetic hostname",
    required_change: "obtain the dependency address through genuine runtime configuration or source-compatible discovery",
}];

const PRODUCTION_FORBIDDEN_MARKERS: &[ForbiddenMarker] = &[
    ForbiddenMarker {
        rule: "traffic_e2e_environment",
        marker: "traffic_e2e_",
        reason: "code depends on a traffic-e2e-owned environment variable",
        required_change: "manage the application-owned value through backend-rewrite startup env",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.18.",
        reason: "code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "fake_ip_range",
        marker: "198.19.",
        reason: "code depends on the replay fake-IP range",
        required_change: "remove the replay address and use the dependency address supplied by the real runtime contract",
    },
    ForbiddenMarker {
        rule: "local_runtime_path",
        marker: ".traffic-e2e/local",
        reason: "code reads traffic-e2e private runtime state",
        required_change: "remove the private runtime-state dependency and use an application-owned input contract",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "expected-response-after.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies.jsonl",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "dependencies-debug.jsonl",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "assertions.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "fake_dns_registry.json",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "progress.yaml",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "replay-progress.yaml",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
    ForbiddenMarker {
        rule: "recording_artifact",
        marker: "comparison-progress.yaml",
        reason: "code consumes a replay or recording artifact",
        required_change: "derive the behavior from the source contract instead of traffic-e2e artifacts",
    },
];

const SOURCE_HARDCODE_MARKERS: &[ForbiddenMarker] = &[
    ForbiddenMarker {
        rule: "source_hardcoded_domain",
        marker: "sample.test",
        reason: "new code hardcodes a source-sensitive public domain without source-code proof",
        required_change: "prove the same value is hardcoded in production source code, add a matching Hardcode-Source-Evidence commit trailer, and rerun with --hardcode-ai-verified TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN; configuration-file values must remain configuration",
    },
    ForbiddenMarker {
        rule: "source_hardcoded_domain",
        marker: "demo.test",
        reason: "new code hardcodes a source-sensitive public domain without source-code proof",
        required_change: "prove the same value is hardcoded in production source code, add a matching Hardcode-Source-Evidence commit trailer, and rerun with --hardcode-ai-verified TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN; configuration-file values must remain configuration",
    },
];

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct SourceLocation {
    file: PathBuf,
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct SourceEvidence {
    repository: String,
    revision: String,
    file: PathBuf,
    line: usize,
    column: usize,
}

impl fmt::Display for SourceEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}@{}:{}:{}:{}",
            self.repository,
            self.revision,
            self.file.display(),
            self.line,
            self.column
        )
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.file.display(),
            self.line,
            self.column
        )
    }
}

#[cfg(test)]
fn inspect(
    target_root: &Path,
    pr_base: &str,
    hardcode_ai_verified: &[String],
) -> Result<ReplayIsolationReport> {
    let added = crate::rewrite::source_diff::added_rust_lines(target_root, pr_base)?;
    inspect_added(target_root, added, hardcode_ai_verified)
}

pub(super) fn inspect_at_base(
    target_root: &Path,
    base: &str,
    hardcode_ai_verified: &[String],
) -> Result<ReplayIsolationReport> {
    let added = changed_rust_lines(target_root, base)?;
    inspect_added(target_root, added, hardcode_ai_verified)
}

fn inspect_added(
    target_root: &Path,
    added: AddedRustLines,
    hardcode_ai_verified: &[String],
) -> Result<ReplayIsolationReport> {
    let approvals = parse_approvals(hardcode_ai_verified)?;
    let mut violations = Vec::new();
    let mut hardcode_matches = BTreeSet::new();

    for added_line in &added.lines {
        let lower = added_line.text.to_ascii_lowercase();
        for marker in ALL_RUST_FORBIDDEN_MARKERS {
            for byte_offset in marker_offsets(&lower, marker.marker) {
                violations.push(violation(added_line, marker, byte_offset));
            }
        }
        if is_production_rust_path(&added_line.file) {
            for marker in PRODUCTION_FORBIDDEN_MARKERS {
                for byte_offset in marker_offsets(&lower, marker.marker) {
                    violations.push(violation(added_line, marker, byte_offset));
                }
            }
        }
        for marker in SOURCE_HARDCODE_MARKERS {
            for byte_offset in marker_offsets(&lower, marker.marker) {
                let location = location(added_line, byte_offset);
                hardcode_matches.insert(location.clone());
                if !approvals.contains_key(&location) {
                    violations.push(violation(added_line, marker, byte_offset));
                }
            }
        }
    }

    for approval in approvals.keys() {
        ensure!(
            hardcode_matches.contains(approval),
            "--hardcode-ai-verified {approval} does not match a newly added sample.test or demo.test occurrence"
        );
    }
    if !approvals.is_empty() {
        for approval in approvals.keys() {
            ensure!(
                committed_hardcode_exists(target_root, approval)?,
                "--hardcode-ai-verified {approval} must refer to a committed occurrence; commit the target line and its Hardcode-Source-Evidence trailer first"
            );
        }
        let evidenced = source_evidence(target_root, &added.merge_base)?;
        for (target, source) in &approvals {
            match evidenced.get(target) {
                Some(committed) if committed == source => {}
                Some(committed) => anyhow::bail!(
                    "--hardcode-ai-verified {target}={source} does not match committed trailer `Hardcode-Source-Evidence: {target} <= {committed}`"
                ),
                None => anyhow::bail!(
                    "--hardcode-ai-verified {target}={source} requires commit trailer `Hardcode-Source-Evidence: {target} <= {source}`"
                ),
            }
        }
    }

    violations.sort();
    let omitted_violations = violations.len().saturating_sub(MAX_REPORTED_VIOLATIONS);
    violations.truncate(MAX_REPORTED_VIOLATIONS);
    let status = if violations.is_empty() && omitted_violations == 0 {
        ReplayIsolationStatus::Passed
    } else {
        ReplayIsolationStatus::Failed
    };
    Ok(ReplayIsolationReport {
        schema_version: 2,
        gate: GATE_NAME.to_string(),
        status,
        scanned_files: added.scanned_files,
        scanned_added_lines: added.lines.len(),
        violations,
        omitted_violations,
    })
}

fn violation(
    added_line: &AddedLine,
    marker: &ForbiddenMarker,
    byte_offset: usize,
) -> ReplayIsolationViolation {
    ReplayIsolationViolation {
        file: added_line.file.clone(),
        line: added_line.line,
        column: column_at(&added_line.text, byte_offset),
        rule: marker.rule.to_string(),
        matched: marker.marker.to_string(),
        reason: marker.reason.to_string(),
        required_change: marker.required_change.to_string(),
    }
}

fn location(added_line: &AddedLine, byte_offset: usize) -> SourceLocation {
    SourceLocation {
        file: added_line.file.clone(),
        line: added_line.line,
        column: column_at(&added_line.text, byte_offset),
    }
}

fn column_at(value: &str, byte_offset: usize) -> usize {
    value[..byte_offset].chars().count() + 1
}

fn marker_offsets(value: &str, marker: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut searched = 0;
    while let Some(relative) = value[searched..].find(marker) {
        let offset = searched + relative;
        offsets.push(offset);
        searched = offset + marker.len();
    }
    offsets
}

fn parse_approvals(raw: &[String]) -> Result<BTreeMap<SourceLocation, SourceEvidence>> {
    let mut approvals = BTreeMap::new();
    for raw_approval in raw {
        let (target, source) = raw_approval.split_once('=').context(
            "expected TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN",
        )?;
        let target = parse_location(target.trim()).with_context(|| {
            format!("invalid --hardcode-ai-verified target in {raw_approval:?}")
        })?;
        let source = parse_source_evidence(source.trim()).with_context(|| {
            format!("invalid --hardcode-ai-verified source in {raw_approval:?}")
        })?;
        ensure!(
            approvals.insert(target, source).is_none(),
            "duplicate --hardcode-ai-verified target in {raw_approval:?}"
        );
    }
    Ok(approvals)
}

fn parse_location(raw: &str) -> Result<SourceLocation> {
    let (file_and_line, column) = raw.rsplit_once(':').context("expected FILE:LINE:COLUMN")?;
    let (file, line) = file_and_line
        .rsplit_once(':')
        .context("expected FILE:LINE:COLUMN")?;
    let file = PathBuf::from(file);
    ensure!(
        is_safe_target_relative_rust_path(&file),
        "file must be a relative Rust source path"
    );
    let line = line.parse::<usize>().context("line is not a number")?;
    let column = column.parse::<usize>().context("column is not a number")?;
    ensure!(line > 0, "line must be positive");
    ensure!(column > 0, "column must be positive");
    Ok(SourceLocation { file, line, column })
}

/// Commit trailers are quality inputs even when no source file changed.
pub(in crate::rewrite) fn source_evidence_unchanged(
    target_root: &Path,
    reviewed_head: &str,
) -> Result<bool> {
    let range = format!("{reviewed_head}..HEAD");
    let messages = git_text(target_root, &["log", "--format=%B%x00", &range])?;
    Ok(!messages
        .split('\0')
        .flat_map(str::lines)
        .any(|line| line.trim().starts_with(SOURCE_EVIDENCE_TRAILER)))
}

fn source_evidence(
    target_root: &Path,
    merge_base: &str,
) -> Result<BTreeMap<SourceLocation, SourceEvidence>> {
    let range = format!("{merge_base}..HEAD");
    let messages = git_text(target_root, &["log", "--format=%B%x00", &range])?;
    let mut evidence = BTreeMap::new();
    for message in messages.split('\0') {
        for line in message.lines() {
            let Some(trailer) = line.trim().strip_prefix(SOURCE_EVIDENCE_TRAILER) else {
                continue;
            };
            let (target, source) = trailer
                .trim()
                .split_once(" <= ")
                .context("Hardcode-Source-Evidence must use `TARGET_FILE:LINE:COLUMN <= SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN`")?;
            let target = parse_location(target.trim())
                .context("invalid target location in Hardcode-Source-Evidence")?;
            let source = parse_source_evidence(source.trim())
                .context("invalid source location in Hardcode-Source-Evidence")?;
            ensure!(
                evidence.insert(target.clone(), source).is_none(),
                "duplicate Hardcode-Source-Evidence target {target}"
            );
        }
    }
    Ok(evidence)
}

fn parse_source_evidence(value: &str) -> Result<SourceEvidence> {
    let (repository, revision_and_source) = value
        .rsplit_once('@')
        .context("source evidence is missing SOURCE_REPOSITORY@SOURCE_REVISION")?;
    let (revision, source_location) = revision_and_source
        .split_once(':')
        .context("source evidence is missing :SOURCE_FILE:LINE:COLUMN")?;
    let (source_file_and_line, source_column) = source_location
        .rsplit_once(':')
        .context("source evidence is missing SOURCE_FILE:LINE:COLUMN")?;
    let (source_file, source_line) = source_file_and_line
        .rsplit_once(':')
        .context("source evidence is missing SOURCE_FILE:LINE:COLUMN")?;
    ensure!(!repository.trim().is_empty(), "source repository is empty");
    ensure!(
        (7..=64).contains(&revision.len()) && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "source revision must be a 7-64 digit hexadecimal commit ID"
    );
    let file = PathBuf::from(source_file);
    ensure!(
        is_safe_production_source_path(&file),
        "source evidence file {:?} must be a relative production source-code path; configuration, resource, test, and example files cannot justify target code hardcoding",
        file
    );
    let line = source_line
        .parse::<usize>()
        .context("source line is not a number")?;
    let column = source_column
        .parse::<usize>()
        .context("source column is not a number")?;
    ensure!(line > 0, "source line must be positive");
    ensure!(column > 0, "source column must be positive");
    Ok(SourceEvidence {
        repository: repository.trim().to_string(),
        revision: revision.to_string(),
        file,
        line,
        column,
    })
}

fn is_safe_production_source_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.components().any(|component| {
            matches!(component, Component::Normal(value) if NON_PRODUCTION_SOURCE_DIRECTORIES.contains(&value.to_string_lossy().as_ref()))
        })
        && path.extension().is_some_and(|extension| {
            PRODUCTION_SOURCE_EXTENSIONS.contains(&extension.to_string_lossy().as_ref())
        })
}

fn committed_hardcode_exists(target_root: &Path, location: &SourceLocation) -> Result<bool> {
    let object_path = crate::rewrite::source_diff::git_object_path(target_root, &location.file)?;
    let object = format!("HEAD:{}", object_path.display());
    let output = Command::new("git")
        .arg("-C")
        .arg(target_root)
        .args(["show", &object])
        .output()
        .with_context(|| format!("failed to read committed target source {:?}", location.file))?;
    if !output.status.success() {
        return Ok(false);
    }
    let source = String::from_utf8(output.stdout)
        .with_context(|| format!("committed target source {:?} is not UTF-8", location.file))?;
    let Some(line) = source.lines().nth(location.line - 1) else {
        return Ok(false);
    };
    let lower = line.to_ascii_lowercase();
    Ok(SOURCE_HARDCODE_MARKERS.iter().any(|marker| {
        marker_offsets(&lower, marker.marker)
            .into_iter()
            .any(|offset| column_at(line, offset) == location.column)
    }))
}

#[cfg(test)]
#[path = "target_replay_isolation_tests.rs"]
mod tests;
