use std::fmt::Write as _;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::{AppConfig, HttpGatewayRuleConfig};

const RULE_HEADER: &str = "[[http_gateway.rules]]";

pub(super) fn parse_and_validate(raw: &str, path: &Path) -> Result<AppConfig> {
    let config = toml::from_str::<AppConfig>(raw)
        .with_context(|| format!("failed to parse recorder config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid recorder config {}", path.display()))?;
    Ok(config)
}

pub(super) fn find_rule<'a>(
    config: &'a AppConfig,
    name: &str,
) -> Result<(usize, &'a HttpGatewayRuleConfig)> {
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

pub(super) fn rule_range(raw: &str, rule_index: usize, rule_count: usize) -> Result<Range<usize>> {
    let ranges = http_rule_ranges(raw);
    ensure!(
        ranges.len() == rule_count,
        "could not associate parsed HTTP gateway rules with their source ranges"
    );
    Ok(ranges[rule_index].clone())
}

pub(super) fn find_managed_block(
    raw: &str,
    within: &Range<usize>,
    begin_marker: &str,
    end_marker: &str,
    label: &str,
) -> Result<Option<Range<usize>>> {
    let mut open = None;
    let mut blocks = Vec::new();
    for line in source_lines(raw) {
        match raw[line.clone()].trim() {
            value if value == begin_marker => {
                ensure!(
                    open.is_none(),
                    "nested AI-managed {label} blocks are invalid"
                );
                open = Some(line.start);
            }
            value if value == end_marker => {
                let start = open.take().with_context(|| {
                    format!("AI-managed {label} end marker has no begin marker")
                })?;
                blocks.push(start..line.end);
            }
            _ => {}
        }
    }
    ensure!(
        open.is_none(),
        "AI-managed {label} block is missing its end marker"
    );
    let matches = blocks
        .into_iter()
        .filter(|block| block.start >= within.start && block.end <= within.end)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() <= 1,
        "selected rule contains multiple AI-managed {label} blocks"
    );
    Ok(matches.into_iter().next())
}

pub(super) fn assignment_count(source: &str, field: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            line.trim()
                .strip_prefix(field)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .count()
}

pub(super) fn insertion_before_assignment(
    raw: &str,
    within: &Range<usize>,
    field: &str,
) -> Option<usize> {
    source_lines(raw)
        .into_iter()
        .filter(|line| line.start >= within.start && line.end <= within.end)
        .find(|line| {
            raw[line.clone()]
                .trim()
                .strip_prefix(field)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .map(|line| line.start)
}

pub(super) fn newline(raw: &str) -> &'static str {
    if raw.contains("\r\n") { "\r\n" } else { "\n" }
}

pub(super) fn managed_block_diff(
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

fn http_rule_ranges(raw: &str) -> Vec<Range<usize>> {
    array_table_ranges(raw, RULE_HEADER)
}

pub(super) fn array_table_ranges(raw: &str, header: &str) -> Vec<Range<usize>> {
    let lines = source_lines(raw);
    let mut ranges = Vec::new();
    for (line_index, line) in lines.iter().enumerate() {
        if raw[line.clone()].trim() != header {
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

fn source_lines(raw: &str) -> Vec<Range<usize>> {
    let mut start = 0;
    let mut lines = Vec::new();
    for segment in raw.split_inclusive('\n') {
        let end = start + segment.len();
        lines.push(start..end);
        start = end;
    }
    if !raw.is_empty() && start < raw.len() {
        lines.push(start..raw.len());
    }
    lines
}
