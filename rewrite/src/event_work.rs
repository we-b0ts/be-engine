//! Convert event-analysis findings into independent implementer assignments.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, PathBuf},
};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Target,
    Rule,
    EngineGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Reproduced,
    SourceProven,
    Hypothesis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub root_cause: String,
    pub summary: String,
    pub kind: Kind,
    pub basis: Basis,
    pub sequences: BTreeSet<u64>,
    #[serde(default)]
    pub code_paths: BTreeSet<PathBuf>,
    #[serde(default)]
    pub blocked_by: BTreeSet<String>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchPlan {
    pub implementers: Vec<Finding>,
    pub coordinator: Vec<Finding>,
    pub waiting: Vec<Finding>,
}

pub fn plan(findings: Vec<Finding>, max_implementers: usize) -> Result<DispatchPlan> {
    ensure!(
        (1..=16).contains(&max_implementers),
        "session supports 1 to 16 implementers"
    );
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
            finding.code_paths.iter().all(|path| {
                !path.as_os_str().is_empty()
                    && path
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
            }),
            "finding code paths must be relative to the Target repository"
        );
        if let Some(previous) = merged.get(&finding.root_cause) {
            ensure!(
                previous.kind == finding.kind,
                "conflicting dispositions for {}",
                finding.root_cause
            );
            finding.sequences.extend(&previous.sequences);
            finding
                .code_paths
                .extend(previous.code_paths.iter().cloned());
            finding
                .blocked_by
                .extend(previous.blocked_by.iter().cloned());
            if previous.basis < finding.basis {
                finding.summary.clone_from(&previous.summary);
                finding.basis = previous.basis;
            }
        }
        merged.insert(finding.root_cause.clone(), finding);
    }
    let mut findings: Vec<_> = merged.into_values().collect();
    findings.sort_by_key(|finding| {
        (
            finding.basis,
            *finding.sequences.first().expect("validated"),
        )
    });
    let mut dispatch = DispatchPlan::default();
    for finding in findings {
        if finding.basis == Basis::Hypothesis
            || finding.kind == Kind::EngineGap
            || finding.code_paths.is_empty()
        {
            dispatch.coordinator.push(finding);
        } else if !finding.blocked_by.is_empty()
            || dispatch.implementers.len() >= max_implementers
            || dispatch.implementers.iter().any(|active| {
                active.code_paths.iter().any(|left| {
                    finding
                        .code_paths
                        .iter()
                        .any(|right| left.starts_with(right) || right.starts_with(left))
                })
            })
        {
            dispatch.waiting.push(finding);
        } else {
            dispatch.implementers.push(finding);
        }
    }
    Ok(dispatch)
}
