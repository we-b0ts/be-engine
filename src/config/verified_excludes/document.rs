use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::VerifiedApiExclude;
use crate::config::AppConfig;

const SECTION_HEADER: &str = "[http_gateway.verified_excludes]";
const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED VERIFIED API EXCLUDES";
const END_MARKER: &str = "# END AI-MANAGED VERIFIED API EXCLUDES";

pub(super) struct ManagedUpdate {
    pub updated: String,
    pub before: BTreeSet<VerifiedApiExclude>,
    pub after: BTreeSet<VerifiedApiExclude>,
    pub added: Vec<VerifiedApiExclude>,
    pub changed: bool,
    pub diff: String,
}

pub(super) fn plan_managed_update(
    original: &str,
    config_path: &Path,
    configured: Vec<VerifiedApiExclude>,
    candidate: &VerifiedApiExclude,
    eligible: bool,
) -> Result<ManagedUpdate> {
    let block = managed_block(original)?;
    ensure_block_owns_apis(&original[block.clone()])?;
    let before = configured.into_iter().collect::<BTreeSet<_>>();
    let mut after = before.clone();
    if eligible {
        after.insert(candidate.clone());
    }
    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let old_block = &original[block.clone()];
    let new_block = render_managed_block(&after, newline, old_block.ends_with('\n'));
    let updated = if eligible {
        replace_block(original, block.clone(), &new_block)
    } else {
        original.to_string()
    };
    validate_config(&updated, config_path)
        .context("generated recorder config failed validation")?;
    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let changed = updated != original;
    let diff = if changed {
        managed_block_diff(config_path, original, block.start, old_block, &new_block)
    } else {
        String::new()
    };
    Ok(ManagedUpdate {
        updated,
        before,
        after,
        added,
        changed,
        diff,
    })
}

fn validate_config(raw: &str, path: &Path) -> Result<()> {
    let config = toml::from_str::<AppConfig>(raw)
        .with_context(|| format!("failed to parse recorder config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid recorder config {}", path.display()))
}

fn managed_block(raw: &str) -> Result<Range<usize>> {
    let lines = source_lines(raw);
    let section_starts = lines
        .iter()
        .filter(|line| raw[(*line).clone()].trim() == SECTION_HEADER)
        .collect::<Vec<_>>();
    ensure!(
        section_starts.len() == 1,
        "recorder config must contain exactly one {SECTION_HEADER} section"
    );
    let section_start = section_starts[0].start;
    let section_end = lines
        .iter()
        .find(|line| {
            line.start > section_start && raw[(*line).clone()].trim_start().starts_with('[')
        })
        .map_or(raw.len(), |line| line.start);
    let mut open = None;
    let mut blocks = Vec::new();
    for line in &lines {
        if line.start < section_start || line.end > section_end {
            continue;
        }
        match raw[line.clone()].trim() {
            BEGIN_MARKER => {
                ensure!(open.is_none(), "nested verified exclude blocks are invalid");
                open = Some(line.start);
            }
            END_MARKER => {
                let start = open
                    .take()
                    .context("verified exclude end marker has no begin marker")?;
                blocks.push(start..line.end);
            }
            _ => {}
        }
    }
    ensure!(
        open.is_none(),
        "verified exclude block is missing its end marker"
    );
    ensure!(
        blocks.len() == 1,
        "verified excludes section must contain exactly one AI-managed block, found {}",
        blocks.len()
    );
    Ok(blocks.remove(0))
}

fn ensure_block_owns_apis(block: &str) -> Result<()> {
    let assignments = block
        .lines()
        .filter(|line| {
            line.trim()
                .strip_prefix("apis")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .count();
    ensure!(
        assignments == 1,
        "AI-managed verified excludes block must contain exactly one apis assignment"
    );
    Ok(())
}

fn render_managed_block(
    apis: &BTreeSet<VerifiedApiExclude>,
    newline: &str,
    trailing_newline: bool,
) -> String {
    let mut output = String::new();
    writeln_with(&mut output, BEGIN_MARKER, newline);
    writeln_with(&mut output, "apis = [", newline);
    for api in apis {
        let rule = toml::Value::String(api.rule.clone()).to_string();
        let method = toml::Value::String(api.method.clone()).to_string();
        let path_pattern = toml::Value::String(api.path_pattern.clone()).to_string();
        writeln_with(
            &mut output,
            &format!("  {{ rule = {rule}, method = {method}, path_pattern = {path_pattern} }},"),
            newline,
        );
    }
    writeln_with(&mut output, "]", newline);
    output.push_str(END_MARKER);
    if trailing_newline {
        output.push_str(newline);
    }
    output
}

fn replace_block(original: &str, block: Range<usize>, replacement: &str) -> String {
    let mut updated = String::with_capacity(original.len() + replacement.len());
    updated.push_str(&original[..block.start]);
    updated.push_str(replacement);
    updated.push_str(&original[block.end..]);
    updated
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

fn writeln_with(output: &mut String, line: &str, newline: &str) {
    output.push_str(line);
    output.push_str(newline);
}

fn source_lines(raw: &str) -> Vec<Range<usize>> {
    let mut start = 0;
    let mut lines = Vec::new();
    for segment in raw.split_inclusive('\n') {
        let end = start + segment.len();
        lines.push(start..end);
        start = end;
    }
    if start < raw.len() {
        lines.push(start..raw.len());
    }
    lines
}
