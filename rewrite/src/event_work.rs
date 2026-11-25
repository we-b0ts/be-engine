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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Findings {
    pub first_unmatched: Option<Finding>,
    #[serde(default)]
    pub others: Vec<Finding>,
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

/// Validate reviewed findings and merge entries with the same group ID.
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
            finding.scope = match (previous.scope.as_deref(), finding.scope) {
                (Some(previous), Some(current)) if previous != current => Some("shared".into()),
                (previous, current) => current.or_else(|| previous.map(str::to_owned)),
            };
        }
        merged.insert(finding.root_cause.clone(), finding);
    }
    let mut findings: Vec<_> = merged.into_values().collect();
    findings.sort_by_key(|finding| *finding.sequences.first().expect("validated"));
    Ok(findings)
}
