use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::config::{fingerprint, load_replay_policy};
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

#[derive(Debug, Clone, Serialize)]
pub struct ResponseRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub assertion_report: PathBuf,
    pub assertion_fingerprint: String,
    pub aggregate_report: PathBuf,
    pub aggregate_fingerprint: String,
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
    ensure!(
        !feedback.json_pointers.is_empty(),
        "at least one --json-pointer is required"
    );
    let (method, path_pattern) = parse_api(&feedback.api)?;
    ensure!(
        method == method.to_ascii_uppercase(),
        "API method must use uppercase canonical form"
    );
    let requested = feedback
        .json_pointers
        .iter()
        .map(|pointer| {
            validate_json_pointer(pointer)?;
            Ok(pointer.clone())
        })
        .collect::<Result<BTreeSet<_>>>()?;

    let original = fs::read_to_string(&feedback.policy_path).with_context(|| {
        format!(
            "failed to read replay policy {}",
            feedback.policy_path.display()
        )
    })?;
    let loaded = load_replay_policy(&feedback.policy_path)?;
    ensure!(
        loaded.document.version >= 2,
        "response rules require replay policy version 2"
    );

    let assertion_bytes = read_regular(&feedback.assertion_report, "assertion report")?;
    let assertions: AssertionEvidence =
        serde_json::from_slice(&assertion_bytes).context("invalid assertion report")?;
    ensure!(
        assertions.expected_response == "assertions_only"
            && assertions.assertion_mode == "runner_owned",
        "response rule planning requires runner-owned assertion evidence"
    );
    ensure!(
        assertions.policy_fingerprint.as_deref() == Some(loaded.fingerprint.as_str()),
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
    let matching = assertions
        .cases
        .iter()
        .filter_map(|case| {
            let response = case.response.as_ref()?;
            (response.method.eq_ignore_ascii_case(method)
                && path_pattern_matches(path_pattern, &response.path))
            .then_some((case, response))
        })
        .collect::<Vec<_>>();
    ensure!(
        !matching.is_empty(),
        "assertion report contains no cases for {}",
        feedback.api
    );
    ensure!(
        matching.len() == assertions.cases.len(),
        "assertion report contains cases outside the requested canonical API group"
    );
    let mut observed_difference = false;
    for (case, response) in &matching {
        ensure!(
            aggregate_cases.contains(&case.case_id),
            "aggregate report does not cover assertion case {:?}",
            case.case_id
        );
        ensure!(
            response.body_mode == "json_structural",
            "response rules require structural JSON assertion evidence"
        );
        for difference in &response.differences {
            ensure!(
                difference_supports_rule(feedback.kind, difference, &requested),
                "case {:?} has an unsupported or undeclared response difference at {}",
                case.case_id,
                difference.pointer
            );
            observed_difference = true;
        }
        for pointer in &requested {
            ensure!(
                response.candidates(feedback.kind).contains(pointer)
                    || response
                        .applied_rule_ids(feedback.kind)
                        .contains(&response_rule_id(feedback.kind, &feedback.api, pointer))
                    || response.differences.is_empty(),
                "case {:?} does not provide {:?} evidence for {}",
                case.case_id,
                feedback.kind,
                pointer
            );
        }
    }
    ensure!(
        observed_difference
            || requested.iter().all(|pointer| {
                response_rule_map(&loaded.document.response_rules, feedback.kind)
                    .get(&feedback.api)
                    .is_some_and(|pointers| pointers.contains(pointer))
            }),
        "assertion evidence contains no differing field selected by the proposed rule"
    );

    let mut updated_rules = loaded.document.response_rules.clone();
    let fields = response_rule_map_mut(&mut updated_rules, feedback.kind)
        .entry(feedback.api.clone())
        .or_default();
    let before = fields.iter().cloned().collect::<BTreeSet<_>>();
    fields.extend(requested.iter().cloned());
    fields.sort();
    fields.dedup();
    let added = requested
        .difference(&before)
        .map(|pointer| response_rule_id(feedback.kind, &feedback.api, pointer))
        .collect::<Vec<_>>();
    let updated = replace_response_rules(&original, &updated_rules)?;
    let changed = updated != original;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ response_rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_response_rules(&updated_rules)?
                .lines()
                .map(|line| format!("+{line}\n"))
                .collect::<String>()
        )
    } else {
        String::new()
    };
    Ok(ResponseRulePlan {
        policy_path: feedback.policy_path.clone(),
        original,
        updated,
        report: ResponseRuleReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            assertion_report: feedback.assertion_report,
            assertion_fingerprint: fingerprint(&assertion_bytes),
            aggregate_report: feedback.aggregate_report,
            aggregate_fingerprint: fingerprint(&aggregate_bytes),
            kind: feedback.kind,
            api: feedback.api,
            json_pointers: requested.into_iter().collect(),
            matching_cases: matching.len(),
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
struct AssertionCaseEvidence {
    case_id: String,
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

fn replace_response_rules(
    original: &str,
    rules: &super::response::ResponseRules,
) -> Result<String> {
    let rendered = render_response_rules(rules)?;
    let mut offset = 0;
    let mut start = None;
    let mut end = original.len();
    for line in original.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if start.is_none() && trimmed.starts_with("response_rules:") && !trimmed.starts_with(' ') {
            start = Some(offset);
        } else if start.is_some() && !trimmed.is_empty() && !trimmed.starts_with([' ', '#']) {
            end = offset;
            break;
        }
        offset += line.len();
    }
    let mut updated = String::new();
    if let Some(start) = start {
        updated.push_str(&original[..start]);
        updated.push_str(&rendered);
        updated.push_str(&original[end..]);
    } else {
        updated.push_str(original);
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(&rendered);
    }
    let document: super::config::ReplayPolicyDocument =
        serde_yaml::from_str(&updated).context("generated replay policy is invalid YAML")?;
    super::config::validate_document(&document).context("generated replay policy is invalid")?;
    Ok(updated)
}

#[derive(Serialize)]
struct ResponseRulesDocument<'a> {
    response_rules: &'a super::response::ResponseRules,
}

fn render_response_rules(rules: &super::response::ResponseRules) -> Result<String> {
    Ok(serde_yaml::to_string(&ResponseRulesDocument {
        response_rules: rules,
    })?)
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
