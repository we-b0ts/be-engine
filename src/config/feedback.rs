use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{AppConfig, HttpGatewayRuleConfig};

const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED CASE PATH PATTERNS";
const END_MARKER: &str = "# END AI-MANAGED CASE PATH PATTERNS";
const RULE_HEADER: &str = "[[http_gateway.rules]]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CasePathPatternAuthority {
    Focused,
    Authoritative,
}

impl std::fmt::Display for CasePathPatternAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Focused => formatter.write_str("focused"),
            Self::Authoritative => formatter.write_str("authoritative"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CasePathPatternFeedback {
    pub config_path: PathBuf,
    pub rule_name: String,
    pub source_revision: String,
    pub case_source: String,
    pub authority: CasePathPatternAuthority,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CasePathPatternReport {
    pub config: PathBuf,
    pub rule: String,
    pub source_revision: String,
    pub case_source: String,
    pub authority: CasePathPatternAuthority,
    pub no_candidates: bool,
    pub changed: bool,
    pub applied: bool,
    pub patterns_before: Vec<String>,
    pub patterns_after: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub diff: String,
}

#[derive(Debug)]
pub struct CasePathPatternPlan {
    config_path: PathBuf,
    original: String,
    updated: String,
    report: CasePathPatternReport,
}

impl CasePathPatternPlan {
    pub fn report(&self) -> &CasePathPatternReport {
        &self.report
    }

    pub fn apply(self, allow_delete: bool) -> Result<CasePathPatternReport> {
        ensure!(
            !allow_delete || self.report.authority == CasePathPatternAuthority::Authoritative,
            "--allow-delete requires --authority authoritative"
        );
        if !self.report.removed.is_empty() {
            ensure!(
                self.report.authority == CasePathPatternAuthority::Authoritative,
                "focused case feedback must not remove case path patterns"
            );
            ensure!(
                allow_delete,
                "authoritative feedback would remove patterns; rerun apply with --allow-delete after reviewing the plan"
            );
        }

        let current = fs::read_to_string(&self.config_path).with_context(|| {
            format!(
                "failed to reread recorder config {}",
                self.config_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "recorder config changed after planning; rerun plan before applying"
        );

        if self.report.changed {
            write_atomic(&self.config_path, self.updated.as_bytes())?;
        }

        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_case_path_pattern_feedback(
    feedback: CasePathPatternFeedback,
) -> Result<CasePathPatternPlan> {
    validate_feedback_metadata(&feedback)?;

    let metadata = fs::symlink_metadata(&feedback.config_path).with_context(|| {
        format!(
            "failed to inspect recorder config {}",
            feedback.config_path.display()
        )
    })?;
    ensure!(metadata.is_file(), "recorder config must be a regular file");
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to replace a symlinked recorder config"
    );

    let original = fs::read_to_string(&feedback.config_path).with_context(|| {
        format!(
            "failed to read recorder config {}",
            feedback.config_path.display()
        )
    })?;
    let config = parse_and_validate(&original, &feedback.config_path)?;
    let (rule_index, rule) = find_rule(&config, &feedback.rule_name)?;
    let block = find_managed_block(&original, rule_index, config.http_gateway.rules.len())?;
    ensure_block_owns_patterns(&original[block.clone()])?;

    let requested = feedback
        .patterns
        .iter()
        .map(|pattern| validate_feedback_pattern(pattern, rule))
        .collect::<Result<BTreeSet<_>>>()?;
    let before = rule
        .case_path_patterns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if feedback.authority == CasePathPatternAuthority::Focused && requested.is_empty() {
        let patterns = before.into_iter().collect::<Vec<_>>();
        return Ok(CasePathPatternPlan {
            config_path: feedback.config_path.clone(),
            original: original.clone(),
            updated: original,
            report: CasePathPatternReport {
                config: feedback.config_path,
                rule: feedback.rule_name,
                source_revision: feedback.source_revision,
                case_source: feedback.case_source,
                authority: feedback.authority,
                no_candidates: true,
                changed: false,
                applied: false,
                patterns_before: patterns.clone(),
                patterns_after: patterns,
                added: Vec::new(),
                removed: Vec::new(),
                diff: String::new(),
            },
        });
    }
    let after = match feedback.authority {
        CasePathPatternAuthority::Focused => before.union(&requested).cloned().collect(),
        CasePathPatternAuthority::Authoritative => requested,
    };

    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let old_block = &original[block.clone()];
    let new_block = render_managed_block(
        &after,
        &feedback.source_revision,
        newline,
        old_block.ends_with('\n'),
    );
    let mut updated = String::with_capacity(original.len() + new_block.len());
    updated.push_str(&original[..block.start]);
    updated.push_str(&new_block);
    updated.push_str(&original[block.end..]);
    parse_and_validate(&updated, &feedback.config_path)
        .context("generated recorder config failed validation")?;

    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let removed = before.difference(&after).cloned().collect::<Vec<_>>();
    let patterns_before = before.into_iter().collect::<Vec<_>>();
    let patterns_after = after.into_iter().collect::<Vec<_>>();
    let changed = updated != original;
    let diff = if changed {
        managed_block_diff(
            &feedback.config_path,
            &original,
            block.start,
            old_block,
            &new_block,
        )
    } else {
        String::new()
    };

    Ok(CasePathPatternPlan {
        config_path: feedback.config_path.clone(),
        original,
        updated,
        report: CasePathPatternReport {
            config: feedback.config_path,
            rule: feedback.rule_name,
            source_revision: feedback.source_revision,
            case_source: feedback.case_source,
            authority: feedback.authority,
            no_candidates: false,
            changed,
            applied: false,
            patterns_before,
            patterns_after,
            added,
            removed,
            diff,
        },
    })
}

fn validate_feedback_metadata(feedback: &CasePathPatternFeedback) -> Result<()> {
    validate_single_line("rule name", &feedback.rule_name)?;
    validate_single_line("source revision", &feedback.source_revision)?;
    validate_single_line("case source", &feedback.case_source)?;
    Ok(())
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        !value.contains(['\r', '\n']),
        "{label} must fit on one line"
    );
    Ok(())
}

fn parse_and_validate(raw: &str, path: &Path) -> Result<AppConfig> {
    let config = toml::from_str::<AppConfig>(raw)
        .with_context(|| format!("failed to parse recorder config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid recorder config {}", path.display()))?;
    Ok(config)
}

fn find_rule<'a>(config: &'a AppConfig, name: &str) -> Result<(usize, &'a HttpGatewayRuleConfig)> {
    let matches = config
        .http_gateway
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.name.as_deref() == Some(name))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "expected exactly one [[http_gateway.rules]] entry named {name:?}, found {}",
        matches.len()
    );
    Ok(matches[0])
}

fn validate_feedback_pattern(pattern: &str, rule: &HttpGatewayRuleConfig) -> Result<String> {
    ensure!(
        pattern.starts_with('/'),
        "pattern must start with '/': {pattern}"
    );
    ensure!(
        !pattern.contains(['?', '#', '\r', '\n']),
        "pattern must contain only a URI path: {pattern}"
    );

    let segments = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    ensure!(!segments.is_empty(), "pattern must not be the root path");
    let normalized = format!("/{}", segments.join("/"));
    ensure!(
        normalized == pattern,
        "pattern must use canonical path separators with no trailing slash: {pattern}"
    );
    ensure!(
        segments.contains(&"*"),
        "feedback pattern must contain at least one '*' that consumes a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .all(|segment| !segment.contains('*') || *segment == "*"),
        "wildcards must consume exactly one whole path segment: {pattern}"
    );

    if !rule.path_prefixes.is_empty() {
        ensure!(
            rule.path_prefixes
                .iter()
                .any(|prefix| path_matches_prefix(pattern, prefix)),
            "pattern {pattern} is outside the selected rule's path_prefixes"
        );
    }
    Ok(pattern.to_string())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let normalized = prefix.trim_end_matches('/');
    path == normalized || path.starts_with(&format!("{normalized}/"))
}

fn find_managed_block(raw: &str, rule_index: usize, rule_count: usize) -> Result<Range<usize>> {
    let rule_ranges = http_rule_ranges(raw);
    ensure!(
        rule_ranges.len() == rule_count,
        "could not associate parsed HTTP gateway rules with their source ranges"
    );
    let rule_range = &rule_ranges[rule_index];
    let blocks = managed_blocks(raw)?;
    let matches = blocks
        .into_iter()
        .filter(|block| block.start >= rule_range.start && block.end <= rule_range.end)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "selected rule must contain exactly one explicit AI-managed case_path_patterns block, found {}",
        matches.len()
    );
    Ok(matches[0].clone())
}

fn http_rule_ranges(raw: &str) -> Vec<Range<usize>> {
    let lines = source_lines(raw);
    let mut ranges = Vec::new();
    for (line_index, line) in lines.iter().enumerate() {
        if raw[line.clone()].trim() != RULE_HEADER {
            continue;
        }
        let end = lines
            .iter()
            .skip(line_index + 1)
            .find(|candidate| raw[(*candidate).clone()].trim().starts_with('['))
            .map_or(raw.len(), |candidate| candidate.start);
        ranges.push(line.start..end);
    }
    ranges
}

fn managed_blocks(raw: &str) -> Result<Vec<Range<usize>>> {
    let mut open = None;
    let mut blocks = Vec::new();
    for line in source_lines(raw) {
        match raw[line.clone()].trim() {
            BEGIN_MARKER => {
                ensure!(
                    open.is_none(),
                    "nested AI-managed pattern blocks are invalid"
                );
                open = Some(line.start);
            }
            END_MARKER => {
                let start = open
                    .take()
                    .context("AI-managed pattern end marker has no begin marker")?;
                blocks.push(start..line.end);
            }
            _ => {}
        }
    }
    ensure!(
        open.is_none(),
        "AI-managed pattern block is missing its end marker"
    );
    Ok(blocks)
}

fn source_lines(raw: &str) -> Vec<Range<usize>> {
    let mut start = 0;
    let mut lines = Vec::new();
    for segment in raw.split_inclusive('\n') {
        let end = start + segment.len();
        lines.push(start..end);
        start = end;
    }
    if raw.is_empty() {
        Vec::new()
    } else if start < raw.len() {
        lines.push(start..raw.len());
        lines
    } else {
        lines
    }
}

fn ensure_block_owns_patterns(block: &str) -> Result<()> {
    let assignments = block
        .lines()
        .filter(|line| {
            line.trim()
                .strip_prefix("case_path_patterns")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .count();
    ensure!(
        assignments == 1,
        "AI-managed block must contain exactly one case_path_patterns assignment"
    );
    Ok(())
}

fn render_managed_block(
    patterns: &BTreeSet<String>,
    source_revision: &str,
    newline: &str,
    trailing_newline: bool,
) -> String {
    let mut output = String::new();
    let revision = toml::Value::String(source_revision.to_string()).to_string();
    writeln_with(&mut output, BEGIN_MARKER, newline);
    writeln_with(
        &mut output,
        &format!("# source_revision = {revision}"),
        newline,
    );
    writeln_with(&mut output, "case_path_patterns = [", newline);
    for pattern in patterns {
        let quoted = toml::Value::String(pattern.clone()).to_string();
        writeln_with(&mut output, &format!("  {quoted},"), newline);
    }
    writeln_with(&mut output, "]", newline);
    output.push_str(END_MARKER);
    if trailing_newline {
        output.push_str(newline);
    }
    output
}

fn writeln_with(output: &mut String, line: &str, newline: &str) {
    output.push_str(line);
    output.push_str(newline);
}

fn managed_block_diff(
    path: &Path,
    original: &str,
    block_start: usize,
    old_block: &str,
    new_block: &str,
) -> String {
    let start_line = original[..block_start].lines().count() + 1;
    let old_count = old_block.lines().count();
    let new_count = new_block.lines().count();
    let mut diff = format!(
        "--- {0}\n+++ {0}\n@@ -{start_line},{old_count} +{start_line},{new_count} @@\n",
        path.display()
    );
    for line in old_block.lines() {
        let _ = writeln!(diff, "-{line}");
    }
    for line in new_block.lines() {
        let _ = writeln!(diff, "+{line}");
    }
    diff
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect recorder config {}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("recorder config path must have a file name")?
        .to_string_lossy();

    let mut temporary = None;
    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary config file"),
        }
    }
    let (temporary_path, mut file) =
        temporary.context("failed to reserve temporary config file")?;

    let result = (|| -> Result<()> {
        file.write_all(contents)
            .context("failed to write temporary config file")?;
        file.sync_all()
            .context("failed to sync temporary config file")?;
        drop(file);
        fs::set_permissions(&temporary_path, metadata.permissions())
            .context("failed to preserve recorder config permissions")?;
        fs::rename(&temporary_path, path).with_context(|| {
            format!(
                "failed to atomically replace recorder config {}",
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync recorder config directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(test)]
mod tests;
