//! Reviewed Source-event findings and dispatch contracts.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub root_cause: String,
    pub summary: String,
    pub sequences: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl Finding {
    pub fn dispatch_group(&self) -> &str {
        self.group.as_deref().unwrap_or(&self.root_cause)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Findings {
    pub first_unmatched: Option<Finding>,
    #[serde(default)]
    pub others: Vec<Finding>,
    pub apis: Option<Vec<ApiConfirmation>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfirmation {
    pub api: String,
    pub implemented: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchPlan {
    pub implementers: Vec<Finding>,
    pub waiting: Vec<Finding>,
}

pub fn validate_max_implementers(max_implementers: usize) -> Result<()> {
    ensure!(
        (1..=16).contains(&max_implementers),
        "session supports 1 to 16 implementers"
    );
    Ok(())
}

pub fn validate_scope(finding: &Finding) -> Result<()> {
    let scope = finding.scope.as_deref().unwrap_or_default();
    let api = scope
        .strip_prefix("api:")
        .and_then(|api| api.split_once(' '))
        .is_some_and(|(method, path)| {
            !method.is_empty()
                && method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
                && path.starts_with('/')
                && !path.contains(char::is_whitespace)
        });
    let job = scope
        .strip_prefix("job:")
        .is_some_and(|name| !name.is_empty() && !name.contains(char::is_whitespace));
    ensure!(
        api || job || matches!(scope, "startup" | "shutdown"),
        "finding {} needs scope api:METHOD /path, job:NAME, startup, or shutdown",
        finding.root_cause
    );
    let group = finding.group.as_deref().unwrap_or_default();
    ensure!(
        !group.is_empty()
            && group.len() <= 128
            && group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "finding {} needs a canonical dispatch group",
        finding.root_cause
    );
    Ok(())
}

/// Validate reviewed findings and merge entries with the same cause.
pub fn normalize(findings: Vec<Finding>) -> Result<Vec<Finding>> {
    let mut merged = BTreeMap::<String, Finding>::new();
    for mut finding in findings {
        ensure!(
            !finding.root_cause.trim().is_empty() && !finding.summary.trim().is_empty(),
            "finding needs a cause and a summary"
        );
        ensure!(
            !finding.sequences.is_empty() && !finding.sequences.contains(&0),
            "finding needs at least one valid Source event sequence"
        );
        ensure!(
            finding
                .scope
                .as_deref()
                .is_none_or(|scope| !scope.trim().is_empty()),
            "finding scope must be nonempty when supplied"
        );
        if let Some(previous) = merged.get(&finding.root_cause) {
            finding.sequences.extend(&previous.sequences);
            if finding.scope.is_none() {
                finding.scope.clone_from(&previous.scope);
            }
            if finding.group.is_none() {
                finding.group.clone_from(&previous.group);
            }
        }
        merged.insert(finding.root_cause.clone(), finding);
    }
    let mut findings: Vec<_> = merged.into_values().collect();
    findings.sort_by_key(|finding| *finding.sequences.first().expect("validated"));
    Ok(findings)
}
