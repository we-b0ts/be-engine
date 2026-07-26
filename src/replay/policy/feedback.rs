mod document;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use self::document::{render_response_rules, replace_response_rules};
use super::config::{LoadedReplayPolicy, fingerprint, load_replay_policy};
use super::pattern::path_pattern_matches;
use super::response::{ResponseRuleKind, parse_api, response_rule_id, validate_json_pointer};
use crate::config::edit::write_atomic;

#[derive(Debug, Clone)]
pub struct ResponseRuleFeedback {
    pub policy_path: PathBuf,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub assertion_report: PathBuf,
    pub aggregate_report: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DynamicResponseRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub assertion_report: PathBuf,
    pub aggregate_report: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ComparisonResponseRuleFeedback {
    pub policy_path: PathBuf,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub comparison_report: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_report: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_fingerprint: Option<String>,
    pub kind: ResponseRuleKind,
    pub api: String,
    pub json_pointers: Vec<String>,
    pub matching_cases: usize,
    pub changed: bool,
    pub applied: bool,
    pub added_rule_ids: Vec<String>,
    pub diff: String,
}

pub struct ResponseRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    report: ResponseRuleReport,
}

pub type DynamicResponseRuleReport = ResponseRuleReport;
pub type DynamicResponseRulePlan = ResponseRulePlan;

impl ResponseRulePlan {
    pub fn report(&self) -> &ResponseRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<ResponseRuleReport> {
        let current = fs::read_to_string(&self.policy_path).with_context(|| {
            format!(
                "failed to reread replay policy {}",
                self.policy_path.display()
            )
        })?;
        ensure!(
            current == self.original,
            "replay policy changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_response_rule(feedback: ResponseRuleFeedback) -> Result<ResponseRulePlan> {
    let prepared = prepare_response_rule(
        &feedback.policy_path,
        &feedback.api,
        &feedback.json_pointers,
    )?;
    let assertion_bytes = read_regular(&feedback.assertion_report, "assertion report")?;
    let assertions: AssertionEvidence =
        serde_json::from_slice(&assertion_bytes).context("invalid assertion report")?;
    ensure!(
        assertions.expected_response == "assertions_only"
            && assertions.assertion_mode == "runner_owned",
        "response rule planning requires runner-owned assertion evidence"
    );
    ensure!(
        assertions.policy_fingerprint.as_deref() == Some(prepared.loaded.fingerprint.as_str()),
        "assertion report replay policy fingerprint is stale"
    );
    let aggregate_bytes = read_regular(&feedback.aggregate_report, "aggregate report")?;
    let aggregate: AggregateEvidence =
        serde_json::from_slice(&aggregate_bytes).context("invalid aggregate report")?;
    ensure!(
        aggregate.complete && !aggregate.dirty,
        "aggregate replay evidence must be complete and clean"
    );
    ensure!(
        assertions.case_source == aggregate.case_source,
        "assertion and aggregate reports use different case sources"
    );
    let aggregate_cases = aggregate
        .selected_case_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    let assertion_cases = assertions
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        assertion_cases == aggregate_cases,
        "assertion and aggregate reports must cover the same focused API cases"
    );
    let matching_cases = validate_response_evidence(
        &prepared,
        feedback.kind,
        &feedback.api,
        &assertions.cases,
        true,
    )?;
    build_response_rule_plan(
        feedback.policy_path,
        feedback.kind,
        feedback.api,
        prepared,
        matching_cases,
        ResponseRuleEvidence::Replay {
            assertion_report: feedback.assertion_report,
            assertion_fingerprint: fingerprint(&assertion_bytes),
            aggregate_report: feedback.aggregate_report,
            aggregate_fingerprint: fingerprint(&aggregate_bytes),
        },
    )
}

pub fn plan_comparison_response_rule(
    feedback: ComparisonResponseRuleFeedback,
) -> Result<ResponseRulePlan> {
    let prepared = prepare_response_rule(
        &feedback.policy_path,
        &feedback.api,
        &feedback.json_pointers,
    )?;
    let comparison_bytes = read_regular(&feedback.comparison_report, "comparison report")?;
    let comparison: ComparisonEvidence =
        serde_json::from_slice(&comparison_bytes).context("invalid comparison report")?;
    ensure!(
        comparison.version == 2
            && comparison.kind == "comparison_recording_verification"
            && comparison.expected_response == "assertions_only"
            && comparison.assertion_mode == "comparison_recording"
            && comparison.baseline_recheck == "optional_source_consistency",
        "response rule planning requires comparison recording verification evidence"
    );
    ensure!(
        comparison.complete,
        "comparison recording verification evidence must be complete"
    );
    ensure!(
        comparison.policy_fingerprint == prepared.loaded.fingerprint,
        "comparison report replay policy fingerprint is stale"
    );
    ensure!(
        comparison.cases.iter().all(|case| case.response.is_some()),
        "complete comparison report contains an unevaluable case"
    );
    ensure!(
        comparison
            .cases
            .iter()
            .all(|case| case.classification.as_deref() != Some("source_drift")),
        "source-drift comparison evidence cannot authorize a response rule"
    );
    let matching_cases = validate_response_evidence(
        &prepared,
        feedback.kind,
        &feedback.api,
        &comparison.cases,
        false,
    )?;
    build_response_rule_plan(
        feedback.policy_path,
        feedback.kind,
        feedback.api,
        prepared,
        matching_cases,
        ResponseRuleEvidence::Comparison {
            comparison_report: feedback.comparison_report,
            comparison_fingerprint: fingerprint(&comparison_bytes),
        },
    )
}

struct PreparedResponseRule {
    method: String,
    path_pattern: String,
    requested: BTreeSet<String>,
    original: String,
    loaded: LoadedReplayPolicy,
}

enum ResponseRuleEvidence {
    Replay {
        assertion_report: PathBuf,
        assertion_fingerprint: String,
        aggregate_report: PathBuf,
        aggregate_fingerprint: String,
    },
    Comparison {
        comparison_report: PathBuf,
        comparison_fingerprint: String,
    },
}

fn prepare_response_rule(
    policy_path: &Path,
    api: &str,
    json_pointers: &[String],
) -> Result<PreparedResponseRule> {
    ensure!(
        !json_pointers.is_empty(),
        "at least one --json-pointer is required"
    );
    let (method, path_pattern) = parse_api(api)?;
    ensure!(
        method == method.to_ascii_uppercase(),
        "API method must use uppercase canonical form"
    );
    let requested = json_pointers
        .iter()
        .map(|pointer| {
            validate_json_pointer(pointer)?;
            Ok(pointer.clone())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let original = fs::read_to_string(policy_path)
        .with_context(|| format!("failed to read replay policy {}", policy_path.display()))?;
    let loaded = load_replay_policy(policy_path)?;
    ensure!(
        loaded.document.version >= 2,
        "response rules require replay policy version 2"
    );
    Ok(PreparedResponseRule {
        method: method.to_string(),
        path_pattern: path_pattern.to_string(),
        requested,
        original,
        loaded,
    })
}

fn validate_response_evidence(
    prepared: &PreparedResponseRule,
    kind: ResponseRuleKind,
    api: &str,
    cases: &[AssertionCaseEvidence],
    require_all_cases: bool,
) -> Result<usize> {
    let matching = cases
        .iter()
        .filter_map(|case| {
            let response = case.response.as_ref()?;
            (response.method.eq_ignore_ascii_case(&prepared.method)
                && path_pattern_matches(&prepared.path_pattern, &response.path))
            .then_some((case, response))
        })
        .collect::<Vec<_>>();
    ensure!(
        !matching.is_empty(),
        "response evidence contains no cases for {api}"
    );
    ensure!(
        !require_all_cases || matching.len() == cases.len(),
        "response evidence contains cases outside the requested canonical API group"
    );
    let mut observed_difference = false;
    for (case, response) in &matching {
        ensure!(
            response.body_mode == "json_structural",
            "response rules require structural JSON assertion evidence"
        );
        for difference in &response.differences {
            ensure!(
                difference_supports_rule(kind, difference, &prepared.requested),
                "case {:?} has an unsupported or undeclared response difference at {}",
                case.case_id,
                difference.pointer
            );
            observed_difference = true;
        }
        for pointer in &prepared.requested {
            ensure!(
                response.candidates(kind).contains(pointer)
                    || response
                        .applied_rule_ids(kind)
                        .contains(&response_rule_id(kind, api, pointer))
                    || response.differences.is_empty(),
                "case {:?} does not provide {:?} evidence for {}",
                case.case_id,
                kind,
                pointer
            );
        }
    }
    ensure!(
        observed_difference
            || prepared.requested.iter().all(|pointer| {
                response_rule_map(&prepared.loaded.document.response_rules, kind)
                    .get(api)
                    .is_some_and(|pointers| pointers.contains(pointer))
            }),
        "response evidence contains no differing field selected by the proposed rule"
    );
    Ok(matching.len())
}

fn build_response_rule_plan(
    policy_path: PathBuf,
    kind: ResponseRuleKind,
    api: String,
    prepared: PreparedResponseRule,
    matching_cases: usize,
    evidence: ResponseRuleEvidence,
) -> Result<ResponseRulePlan> {
    let mut updated_rules = prepared.loaded.document.response_rules.clone();
    let fields = response_rule_map_mut(&mut updated_rules, kind)
        .entry(api.clone())
        .or_default();
    let before = fields.iter().cloned().collect::<BTreeSet<_>>();
    fields.extend(prepared.requested.iter().cloned());
    fields.sort();
    fields.dedup();
    let added = prepared
        .requested
        .difference(&before)
        .map(|pointer| response_rule_id(kind, &api, pointer))
        .collect::<Vec<_>>();
    let updated = replace_response_rules(&prepared.original, &updated_rules)?;
    let changed = updated != prepared.original;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ response_rules @@\n{}",
            policy_path.display(),
            policy_path.display(),
            render_response_rules(&updated_rules)?
                .lines()
                .map(|line| format!("+{line}\n"))
                .collect::<String>()
        )
    } else {
        String::new()
    };
    let (
        assertion_report,
        assertion_fingerprint,
        aggregate_report,
        aggregate_fingerprint,
        comparison_report,
        comparison_fingerprint,
    ) = match evidence {
        ResponseRuleEvidence::Replay {
            assertion_report,
            assertion_fingerprint,
            aggregate_report,
            aggregate_fingerprint,
        } => (
            Some(assertion_report),
            Some(assertion_fingerprint),
            Some(aggregate_report),
            Some(aggregate_fingerprint),
            None,
            None,
        ),
        ResponseRuleEvidence::Comparison {
            comparison_report,
            comparison_fingerprint,
        } => (
            None,
            None,
            None,
            None,
            Some(comparison_report),
            Some(comparison_fingerprint),
        ),
    };
    Ok(ResponseRulePlan {
        policy_path: policy_path.clone(),
        original: prepared.original,
        updated,
        report: ResponseRuleReport {
            policy: policy_path,
            policy_fingerprint: prepared.loaded.fingerprint,
            assertion_report,
            assertion_fingerprint,
            aggregate_report,
            aggregate_fingerprint,
            comparison_report,
            comparison_fingerprint,
            kind,
            api,
            json_pointers: prepared.requested.into_iter().collect(),
            matching_cases,
            changed,
            applied: false,
            added_rule_ids: added,
            diff,
        },
    })
}

pub fn plan_dynamic_response_rule(
    feedback: DynamicResponseRuleFeedback,
) -> Result<DynamicResponseRulePlan> {
    plan_response_rule(ResponseRuleFeedback {
        policy_path: feedback.policy_path,
        kind: ResponseRuleKind::Dynamic,
        api: feedback.api,
        json_pointers: feedback.json_pointers,
        assertion_report: feedback.assertion_report,
        aggregate_report: feedback.aggregate_report,
    })
}

#[derive(Debug, Deserialize)]
struct AssertionEvidence {
    case_source: String,
    expected_response: String,
    assertion_mode: String,
    policy_fingerprint: Option<String>,
    cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
struct ComparisonEvidence {
    version: u8,
    kind: String,
    expected_response: String,
    assertion_mode: String,
    baseline_recheck: String,
    policy_fingerprint: String,
    complete: bool,
    cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
struct AssertionCaseEvidence {
    case_id: String,
    #[serde(default)]
    classification: Option<String>,
    response: Option<ResponseCaseEvidence>,
}

#[derive(Debug, Deserialize)]
struct ResponseCaseEvidence {
    method: String,
    path: String,
    body_mode: String,
    differences: Vec<DifferenceEvidence>,
    #[serde(default)]
    applied_dynamic_rule_ids: Vec<String>,
    #[serde(default)]
    dynamic_candidates: Vec<String>,
    #[serde(default)]
    applied_unordered_rule_ids: Vec<String>,
    #[serde(default)]
    unordered_candidates: Vec<String>,
}

impl ResponseCaseEvidence {
    fn candidates(&self, kind: ResponseRuleKind) -> &Vec<String> {
        match kind {
            ResponseRuleKind::Dynamic => &self.dynamic_candidates,
            ResponseRuleKind::Unordered => &self.unordered_candidates,
        }
    }

    fn applied_rule_ids(&self, kind: ResponseRuleKind) -> &Vec<String> {
        match kind {
            ResponseRuleKind::Dynamic => &self.applied_dynamic_rule_ids,
            ResponseRuleKind::Unordered => &self.applied_unordered_rule_ids,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DifferenceEvidence {
    pointer: String,
    kind: String,
    expected_type: Option<String>,
    actual_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AggregateEvidence {
    case_source: String,
    selected_case_ids: Vec<String>,
    complete: bool,
    dirty: bool,
}

fn difference_supports_rule(
    kind: ResponseRuleKind,
    difference: &DifferenceEvidence,
    requested: &BTreeSet<String>,
) -> bool {
    if !requested.contains(&difference.pointer) {
        return false;
    }
    match kind {
        ResponseRuleKind::Dynamic => {
            difference.kind == "value_mismatch"
                && difference.expected_type == difference.actual_type
                && difference
                    .expected_type
                    .as_deref()
                    .is_some_and(|kind| matches!(kind, "string" | "number" | "boolean"))
        }
        ResponseRuleKind::Unordered => {
            difference.kind == "array_order_mismatch"
                && difference.expected_type.as_deref() == Some("array")
                && difference.actual_type.as_deref() == Some("array")
        }
    }
}

fn response_rule_map(
    rules: &super::response::ResponseRules,
    kind: ResponseRuleKind,
) -> &std::collections::BTreeMap<String, Vec<String>> {
    match kind {
        ResponseRuleKind::Dynamic => &rules.dynamic,
        ResponseRuleKind::Unordered => &rules.unordered,
    }
}

fn response_rule_map_mut(
    rules: &mut super::response::ResponseRules,
    kind: ResponseRuleKind,
) -> &mut std::collections::BTreeMap<String, Vec<String>> {
    match kind {
        ResponseRuleKind::Dynamic => &mut rules.dynamic,
        ResponseRuleKind::Unordered => &mut rules.unordered,
    }
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

#[cfg(test)]
#[path = "feedback/tests.rs"]
mod tests;
