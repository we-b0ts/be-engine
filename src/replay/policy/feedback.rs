mod document;
mod evidence;
mod justification;
mod model;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::document::{render_response_rules, replace_response_rules};
use self::evidence::{
    AggregateEvidence, AssertionCaseEvidence, AssertionEvidence, ComparisonEvidence,
    difference_supports_rule, response_rule_exists, source_change_overlaps,
};
use super::config::{LoadedReplayPolicy, fingerprint, load_replay_policy};
use super::pattern::path_pattern_matches;
#[cfg(test)]
use super::response::DynamicResponseMechanism;
use super::response::{
    CounterResponseRule, DynamicResponseRule, ResponseRuleKind, parse_api,
    response_locations_overlap, response_rule_id, validate_json_pointer,
};
use crate::config::edit::write_atomic;

use justification::ResponseRuleJustification;
pub use model::{
    ComparisonResponseRuleFeedback, DynamicResponseRuleFeedback, ResponseRuleFeedback,
    ResponseRuleReport,
};

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
        feedback.kind != ResponseRuleKind::Counter,
        "counter response rules require `config comparison` and --comparison-report"
    );
    let justification = justification::validate(
        feedback.kind,
        feedback.dynamic_mechanisms,
        feedback.source_evidence,
        feedback.source_example,
        feedback.target_example,
    )?;
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
        aggregate.complete,
        "aggregate replay evidence must be complete"
    );
    ensure!(
        feedback.kind == ResponseRuleKind::Dynamic || !aggregate.dirty,
        "unordered response rule evidence requires clean aggregate replay evidence"
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
    let response_evidence = validate_response_evidence(
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
        response_evidence,
        justification,
        ResponseRuleEvidence::Replay {
            assertion_report: feedback.assertion_report,
            assertion_fingerprint: fingerprint(&assertion_bytes),
            aggregate_report: feedback.aggregate_report,
            aggregate_fingerprint: fingerprint(&aggregate_bytes),
            aggregate_dirty: aggregate.dirty,
        },
    )
}

pub fn plan_comparison_response_rule(
    feedback: ComparisonResponseRuleFeedback,
) -> Result<ResponseRulePlan> {
    let justification = justification::validate(
        feedback.kind,
        feedback.dynamic_mechanisms,
        feedback.source_evidence,
        feedback.source_example,
        feedback.target_example,
    )?;
    let prepared = prepare_response_rule(
        &feedback.policy_path,
        &feedback.api,
        &feedback.json_pointers,
    )?;
    let comparison_bytes = read_regular(&feedback.comparison_report, "comparison report")?;
    let comparison: ComparisonEvidence =
        serde_json::from_slice(&comparison_bytes).context("invalid comparison report")?;
    ensure!(
        matches!(comparison.version, 3..=5)
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
            .all(
                |case| case.classification.as_deref() != Some("policy_mismatch")
                    && case.policy_mismatch_rule_ids.is_empty()
            ),
        "comparison evidence with unused applicable response rules cannot authorize a new rule"
    );
    let response_evidence = validate_response_evidence(
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
        response_evidence,
        justification,
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
        aggregate_dirty: bool,
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
) -> Result<ResponseEvidenceValidation> {
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
    let mut selected_difference_cases = 0;
    let mut unselected_difference_pointers = BTreeSet::new();
    for (case, response) in &matching {
        ensure!(
            case.matched_source.as_deref() != Some("after") || response.differences.is_empty(),
            "case {:?} already matches the permitted source-after observation",
            case.case_id
        );
        ensure!(
            case.policy_mismatch_rule_ids.is_empty(),
            "case {:?} has unused applicable response rules",
            case.case_id
        );
        if kind != ResponseRuleKind::Counter {
            ensure!(
                !source_change_overlaps(case, &prepared.requested),
                "case {:?} has source changes overlapping the proposed response rule",
                case.case_id
            );
        }
        ensure!(
            response.body_mode == "json_structural",
            "response rules require structural JSON assertion evidence"
        );
        let mut case_has_selected_difference = false;
        for difference in &response.differences {
            let overlaps_requested = prepared
                .requested
                .iter()
                .any(|pointer| response_locations_overlap(pointer, &difference.pointer));
            if overlaps_requested {
                ensure!(
                    difference_supports_rule(kind, difference, &prepared.requested),
                    "case {:?} has an unsupported response difference at selected location {}",
                    case.case_id,
                    difference.pointer
                );
                observed_difference = true;
                case_has_selected_difference = true;
            } else if matches!(kind, ResponseRuleKind::Dynamic | ResponseRuleKind::Counter) {
                unselected_difference_pointers.insert(difference.pointer.clone());
            } else {
                anyhow::bail!(
                    "case {:?} has an unsupported or undeclared response difference at {}",
                    case.case_id,
                    difference.pointer
                );
            }
        }
        selected_difference_cases += usize::from(case_has_selected_difference);
        for pointer in &prepared.requested {
            let has_overlapping_difference = response
                .differences
                .iter()
                .any(|difference| response_locations_overlap(pointer, &difference.pointer));
            ensure!(
                response.candidates(kind).contains(pointer)
                    || response
                        .applied_rule_ids(kind)
                        .contains(&response_rule_id(kind, api, pointer))
                    || (kind == ResponseRuleKind::Dynamic && !has_overlapping_difference)
                    || (kind == ResponseRuleKind::Counter && has_overlapping_difference)
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
                response_rule_exists(&prepared.loaded.document.response_rules, kind, api, pointer)
            }),
        "response evidence contains no differing field selected by the proposed rule"
    );
    Ok(ResponseEvidenceValidation {
        matching_cases: matching.len(),
        selected_difference_cases,
        unselected_difference_pointers: unselected_difference_pointers.into_iter().collect(),
    })
}

struct ResponseEvidenceValidation {
    matching_cases: usize,
    selected_difference_cases: usize,
    unselected_difference_pointers: Vec<String>,
}

fn build_response_rule_plan(
    policy_path: PathBuf,
    kind: ResponseRuleKind,
    api: String,
    prepared: PreparedResponseRule,
    response_evidence: ResponseEvidenceValidation,
    justification: ResponseRuleJustification,
    evidence: ResponseRuleEvidence,
) -> Result<ResponseRulePlan> {
    let mut updated_rules = prepared.loaded.document.response_rules.clone();
    let before = match kind {
        ResponseRuleKind::Dynamic => updated_rules
            .dynamic
            .get(&api)
            .into_iter()
            .flatten()
            .map(|field| field.pointer.clone())
            .collect::<BTreeSet<_>>(),
        ResponseRuleKind::Unordered => updated_rules
            .unordered
            .get(&api)
            .into_iter()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ResponseRuleKind::Counter => updated_rules
            .comparison
            .counter
            .get(&api)
            .into_iter()
            .flatten()
            .map(|field| field.pointer.clone())
            .collect::<BTreeSet<_>>(),
    };
    match kind {
        ResponseRuleKind::Dynamic => {
            let fields = updated_rules.dynamic.entry(api.clone()).or_default();
            for pointer in &prepared.requested {
                let proposed = DynamicResponseRule {
                    pointer: pointer.clone(),
                    mechanisms: justification.dynamic_mechanisms.clone(),
                    source_evidence: justification
                        .source_evidence
                        .clone()
                        .expect("dynamic justification requires source evidence"),
                    source_example: justification
                        .source_example
                        .clone()
                        .expect("dynamic justification requires a source example"),
                    target_example: justification
                        .target_example
                        .clone()
                        .expect("dynamic justification requires a target example"),
                };
                if let Some(existing) = fields.iter_mut().find(|field| field.pointer == *pointer) {
                    *existing = proposed;
                } else {
                    fields.push(proposed);
                }
            }
            fields.sort_by(|left, right| left.pointer.cmp(&right.pointer));
        }
        ResponseRuleKind::Unordered => {
            let fields = updated_rules.unordered.entry(api.clone()).or_default();
            fields.extend(prepared.requested.iter().cloned());
            fields.sort();
            fields.dedup();
        }
        ResponseRuleKind::Counter => {
            let fields = updated_rules
                .comparison
                .counter
                .entry(api.clone())
                .or_default();
            for pointer in &prepared.requested {
                let proposed = CounterResponseRule {
                    pointer: pointer.clone(),
                    source_evidence: justification
                        .source_evidence
                        .clone()
                        .expect("counter justification requires source evidence"),
                    source_example: justification
                        .source_example
                        .clone()
                        .expect("counter justification requires a source example"),
                    target_example: justification
                        .target_example
                        .clone()
                        .expect("counter justification requires a target example"),
                };
                if let Some(existing) = fields.iter_mut().find(|field| field.pointer == *pointer) {
                    *existing = proposed;
                } else {
                    fields.push(proposed);
                }
            }
            fields.sort_by(|left, right| left.pointer.cmp(&right.pointer));
        }
    }
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
        aggregate_dirty,
    ) = match evidence {
        ResponseRuleEvidence::Replay {
            assertion_report,
            assertion_fingerprint,
            aggregate_report,
            aggregate_fingerprint,
            aggregate_dirty,
        } => (
            Some(assertion_report),
            Some(assertion_fingerprint),
            Some(aggregate_report),
            Some(aggregate_fingerprint),
            None,
            None,
            Some(aggregate_dirty),
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
            None,
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
            dynamic_mechanisms: justification.dynamic_mechanisms,
            source_evidence: justification.source_evidence,
            source_example: justification.source_example,
            target_example: justification.target_example,
            matching_cases: response_evidence.matching_cases,
            selected_difference_cases: response_evidence.selected_difference_cases,
            unselected_difference_pointers: response_evidence.unselected_difference_pointers,
            aggregate_dirty,
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
        dynamic_mechanisms: feedback.dynamic_mechanisms,
        source_evidence: Some(feedback.source_evidence),
        source_example: Some(feedback.source_example),
        target_example: Some(feedback.target_example),
        assertion_report: feedback.assertion_report,
        aggregate_report: feedback.aggregate_report,
    })
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
