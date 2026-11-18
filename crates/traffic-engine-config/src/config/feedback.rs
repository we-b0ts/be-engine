use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::HttpGatewayRuleConfig;
use super::edit::write_atomic;
use super::rule_document::whole_file_diff;
use super::{AppConfig, SourceTrafficPolicyConfig};

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
    pub project_config_path: PathBuf,
    pub rules_path: PathBuf,
    pub source_revision: String,
    pub case_source: String,
    pub authority: CasePathPatternAuthority,
    pub patterns: Vec<String>,
    pub incorrect_patterns: Vec<String>,
    pub correction_evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CasePathPatternReport {
    pub rules: PathBuf,
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
    project_config_path: PathBuf,
    rules_path: PathBuf,
    original_project_config: String,
    original_rules: String,
    updated_rules: String,
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

        let current_project_config = fs::read_to_string(&self.project_config_path)?;
        ensure!(
            current_project_config == self.original_project_config,
            "project config changed after planning; rerun plan before applying"
        );
        let current_rules = fs::read_to_string(&self.rules_path)?;
        ensure!(
            current_rules == self.original_rules,
            "source traffic policy changed after planning; rerun plan before applying"
        );

        if self.report.changed {
            write_atomic(&self.rules_path, self.updated_rules.as_bytes())?;
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

    let original_project_config = fs::read_to_string(&feedback.project_config_path)
        .with_context(|| format!("failed to read {}", feedback.project_config_path.display()))?;
    let original_rules = fs::read_to_string(&feedback.rules_path)
        .with_context(|| format!("failed to read {}", feedback.rules_path.display()))?;
    let mut rules = SourceTrafficPolicyConfig::parse(&original_rules, &feedback.rules_path)?;
    let static_config = AppConfig::load_with_source_policy(&feedback.project_config_path, &rules)?;

    let requested = feedback
        .patterns
        .iter()
        .map(|pattern| validate_case_path_pattern(pattern, &static_config.http_gateway.rules))
        .collect::<Result<BTreeSet<_>>>()?;
    let before = rules
        .http
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
            project_config_path: feedback.project_config_path,
            rules_path: feedback.rules_path.clone(),
            original_project_config,
            original_rules: original_rules.clone(),
            updated_rules: original_rules,
            report: CasePathPatternReport {
                rules: feedback.rules_path,
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

    rules.http.case_path_patterns = after.iter().cloned().collect();
    rules.http.source_revision = feedback.source_revision.clone();
    AppConfig::load_with_source_policy(&feedback.project_config_path, &rules)?;
    let updated_rules = super::native_policy::render_updated(
        &original_rules,
        &rules,
        &crate::policy::Proof {
            source: format!("{} at {}", feedback.case_source, feedback.source_revision),
            fact: feedback.correction_evidence.clone().unwrap_or_else(|| {
                "Observed Source inventory authorizes these capture paths; comparison permissions remain unchanged.".into()
            }),
        },
    )?;

    let added = after.difference(&before).cloned().collect::<Vec<_>>();
    let removed = before.difference(&after).cloned().collect::<Vec<_>>();
    let corrections_requested = incorrect.iter().cloned().collect::<Vec<_>>();
    let corrections_already_absent = incorrect.difference(&before).cloned().collect::<Vec<_>>();
    let patterns_before = before.into_iter().collect::<Vec<_>>();
    let patterns_after = after.into_iter().collect::<Vec<_>>();
    let changed = updated_rules != original_rules;
    let diff = if changed {
        whole_file_diff(&feedback.rules_path, &original_rules, &updated_rules)
    } else {
        String::new()
    };

    Ok(CasePathPatternPlan {
        project_config_path: feedback.project_config_path,
        rules_path: feedback.rules_path.clone(),
        original_project_config,
        original_rules,
        updated_rules,
        report: CasePathPatternReport {
            rules: feedback.rules_path,
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

pub fn validate_case_path_pattern(
    pattern: &str,
    rules: &[HttpGatewayRuleConfig],
) -> Result<String> {
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

    if !rules.is_empty() {
        ensure!(
            rules.iter().any(|rule| {
                rule.path_prefixes.is_empty()
                    || rule
                        .path_prefixes
                        .iter()
                        .any(|prefix| path_matches_prefix(pattern, prefix))
            }),
            "pattern {pattern} is outside every configured HTTP recording rule's path_prefixes"
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

#[cfg(test)]
mod tests;
