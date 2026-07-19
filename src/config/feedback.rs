use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::HttpGatewayRuleConfig;
use super::edit::write_atomic;
use super::rule_document::{
    assignment_count, find_managed_block, find_rule, managed_block_diff, newline,
    parse_and_validate, rule_range,
};

const BEGIN_MARKER: &str = "# BEGIN AI-MANAGED CASE PATH PATTERNS";
const END_MARKER: &str = "# END AI-MANAGED CASE PATH PATTERNS";

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
    pub incorrect_patterns: Vec<String>,
    pub correction_evidence: Option<String>,
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
    pub corrections_requested: Vec<String>,
    pub corrections_already_absent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction_evidence: Option<String>,
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
            !allow_delete || !self.report.removed.is_empty(),
            "--allow-delete requires at least one explicit --remove-incorrect-pattern"
        );
        if !self.report.removed.is_empty() {
            ensure!(
                allow_delete,
                "corrective feedback would remove explicitly named patterns; rerun apply with --allow-delete after reviewing the plan"
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
    let rule_range = rule_range(&original, rule_index, config.http_gateway.rules.len())?;
    let block = find_managed_block(
        &original,
        &rule_range,
        BEGIN_MARKER,
        END_MARKER,
        "case_path_patterns",
    )?
    .context("selected rule must contain an explicit AI-managed case_path_patterns block")?;
    ensure!(
        assignment_count(&original[block.clone()], "case_path_patterns") == 1,
        "AI-managed block must contain exactly one case_path_patterns assignment"
    );

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
    let incorrect = feedback
        .incorrect_patterns
        .iter()
        .map(|pattern| validate_incorrect_pattern(pattern))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        requested.is_disjoint(&incorrect),
        "a pattern cannot be both requested and marked incorrect"
    );
    match (&feedback.correction_evidence, incorrect.is_empty()) {
        (Some(evidence), false) => validate_single_line("correction evidence", evidence)?,
        (Some(_), true) => {
            anyhow::bail!("correction evidence requires at least one incorrect pattern")
        }
        (None, false) => {
            anyhow::bail!("removing an incorrect AI-managed pattern requires --correction-evidence")
        }
        (None, true) => {}
    }
    if requested.is_empty() && incorrect.is_empty() {
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
                corrections_requested: Vec::new(),
                corrections_already_absent: Vec::new(),
                correction_evidence: None,
                diff: String::new(),
            },
        });
    }
    let mut after = before.union(&requested).cloned().collect::<BTreeSet<_>>();
    for pattern in &incorrect {
        after.remove(pattern);
    }

    let newline = newline(&original);
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
    let corrections_requested = incorrect.iter().cloned().collect::<Vec<_>>();
    let corrections_already_absent = incorrect.difference(&before).cloned().collect::<Vec<_>>();
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
            corrections_requested,
            corrections_already_absent,
            correction_evidence: feedback.correction_evidence,
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
        segments
            .iter()
            .any(|segment| *segment == "*" || *segment == "**"),
        "feedback pattern must contain at least one '*' or '**' wildcard occupying a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .all(|segment| !segment.contains('*') || *segment == "*" || *segment == "**"),
        "wildcards must occupy a whole path segment: {pattern}"
    );
    ensure!(
        segments
            .iter()
            .enumerate()
            .all(|(index, segment)| *segment != "**" || index == segments.len() - 1),
        "'**' catch-all must be the final path segment: {pattern}"
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

fn validate_incorrect_pattern(pattern: &str) -> Result<String> {
    validate_single_line("incorrect pattern", pattern)?;
    ensure!(
        pattern.starts_with('/') && !pattern.contains(['?', '#']),
        "incorrect pattern must be an exact URI path pattern: {pattern}"
    );
    Ok(pattern.to_string())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    let normalized = prefix.trim_end_matches('/');
    path == normalized || path.starts_with(&format!("{normalized}/"))
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

#[cfg(test)]
mod tests;
