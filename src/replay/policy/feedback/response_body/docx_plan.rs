use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};

use super::*;
use crate::replay::assertion::{DocxBodyDifferenceKind, ResponseBodyDifferenceDetail};
use crate::replay::policy::config::LoadedReplayPolicy;
use crate::replay::policy::response::{DocxResponseRules, ResponseBodyRuleMatch};

pub(super) fn plan(
    feedback: ResponseBodyRuleFeedback,
    original: String,
    mut loaded: LoadedReplayPolicy,
    evidence: ResponseBodyPlanningEvidence,
    existing: Option<ResponseBodyRuleMatch>,
) -> Result<ResponseBodyRulePlan> {
    ensure!(
        feedback.unordered_paths.is_empty() && feedback.unordered_joined_string_paths.is_empty(),
        "DOCX response-body rules cannot carry typed collection paths"
    );
    let requested = selectors(&feedback.docx_timestamps);
    ensure!(
        requested.len() == feedback.docx_timestamps.len(),
        "DOCX response-body rule plan repeats a timestamp selector"
    );
    let existing_rules = existing
        .as_ref()
        .map(|rule| rule.docx_timestamps.clone())
        .unwrap_or_default();
    let existing_selectors = selectors(&existing_rules);
    ensure!(
        requested.is_disjoint(&existing_selectors),
        "DOCX response-body rule plan repeats a timestamp already present in the rule"
    );

    let mut discovered = BTreeSet::new();
    let mut examples_observed = BTreeSet::new();
    let mut selected_difference_cases = 0;
    let mut difference_cases = 0;
    let mut effective = existing_rules
        .into_iter()
        .map(|rule| ((rule.part.clone(), rule.element.clone()), rule))
        .collect::<BTreeMap<_, _>>();
    effective.extend(
        feedback
            .docx_timestamps
            .iter()
            .cloned()
            .map(|rule| ((rule.part.clone(), rule.element.clone()), rule)),
    );
    let effective = effective.into_values().collect::<Vec<_>>();

    for case in &evidence.cases {
        ensure!(
            case.policy_mismatch_rule_ids.is_empty(),
            "case {:?} has an unused applicable response rule",
            case.case_id
        );
        ensure!(
            case.source_change_pointers.is_empty(),
            "case {:?} has source changes and cannot authorize a DOCX response rule",
            case.case_id
        );
        if case.passed {
            continue;
        }
        difference_cases += 1;
        ensure!(
            case.candidate_only,
            "case {:?} is not a candidate-only response difference",
            case.case_id
        );
        let response = case
            .response
            .as_ref()
            .with_context(|| format!("case {:?} has no response assertion", case.case_id))?;
        ensure!(
            response.differences.len() == 1
                && response.differences[0].pointer == "$body"
                && matches!(
                    response.differences[0].kind,
                    ResponseDifferenceKind::ExactBodyMismatch
                        | ResponseDifferenceKind::ValueMismatch
                ),
            "case {:?} has differences other than the DOCX body value",
            case.case_id
        );
        let diagnosis = diagnose_response_body(
            &case.expected_body,
            &case.actual_body,
            ResponseBodyCodec::Docx,
        )
        .with_context(|| format!("case {:?} is not a comparable DOCX package", case.case_id))?;
        for rule in &feedback.docx_timestamps {
            if crate::replay::assertion::docx::timestamp_values(
                &case.expected_body,
                &case.actual_body,
                rule,
            )?
            .is_some_and(|(source, target)| {
                source == rule.source_example && target == rule.target_example
            }) {
                examples_observed.insert((rule.part.clone(), rule.element.clone()));
            }
            if let Some(source_after) = &case.source_after_body
                && crate::replay::assertion::docx::timestamp_values(
                    source_after,
                    &case.actual_body,
                    rule,
                )?
                .is_some_and(|(source, target)| {
                    source == rule.source_example && target == rule.target_example
                })
            {
                examples_observed.insert((rule.part.clone(), rule.element.clone()));
            }
        }
        let case_discovered = diagnosis
            .differences
            .iter()
            .filter_map(|difference| match difference {
                ResponseBodyDifferenceDetail::Docx(difference)
                    if difference.kind == DocxBodyDifferenceKind::TimestampMismatch =>
                {
                    Some((
                        difference.part.clone(),
                        difference.element.clone().unwrap_or_default(),
                    ))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        discovered.extend(case_discovered.iter().cloned());
        if (!requested.is_empty() && !case_discovered.is_disjoint(&requested))
            || (requested.is_empty() && diagnosis.candidates_explain_all_differences)
        {
            selected_difference_cases += 1;
        }

        let (matches_before, _) = crate::replay::assertion::docx::evaluate_docx(
            &case.expected_body,
            &case.actual_body,
            &effective,
            case.times,
        )?;
        let matches_after = if !matches_before
            && evidence.source_match == ComparisonSourceMatch::BeforeOrAfter
            && case.source_after_body.is_some()
        {
            crate::replay::assertion::docx::evaluate_docx(
                case.source_after_body.as_deref().unwrap_or_default(),
                &case.actual_body,
                &effective,
                RequestTimes {
                    source: case.source_after_time,
                    target: case.times.target,
                },
            )?
            .0
        } else {
            false
        };
        ensure!(
            matches_before || matches_after,
            "DOCX timestamp rules leave a content or time-validation difference in case {:?}",
            case.case_id
        );
    }
    ensure!(
        difference_cases > 0,
        "response evidence contains no DOCX response-body difference"
    );
    ensure!(
        requested
            .iter()
            .all(|selector| discovered.contains(selector)),
        "reviewed DOCX timestamps were not present in the observed DOCX differences"
    );
    ensure!(
        requested
            .iter()
            .all(|selector| examples_observed.contains(selector)),
        "DOCX timestamp source_example and target_example must match current evidence"
    );

    loaded.document.response_rules.docx.insert(
        feedback.api.clone(),
        DocxResponseRules {
            timestamp: effective.clone(),
        },
    );
    validate_response_rules(&loaded.document.response_rules)?;
    let updated = replace_response_rules(&original, &loaded.document.response_rules)?;
    let changed = updated != original;
    let diff = if changed {
        format!(
            "--- {}\n+++ {}\n@@ response_rules @@\n{}",
            feedback.policy_path.display(),
            feedback.policy_path.display(),
            render_response_rules(&loaded.document.response_rules)?
                .lines()
                .map(|line| format!("+{line}\n"))
                .collect::<String>()
        )
    } else {
        String::new()
    };
    Ok(ResponseBodyRulePlan {
        policy_path: feedback.policy_path.clone(),
        original,
        updated,
        verification: evidence.verification,
        report: ResponseBodyRuleReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            evidence_kind: evidence.kind,
            evidence_report: evidence.report,
            evidence_fingerprint: evidence.fingerprint,
            api: feedback.api.clone(),
            rule_id: response_body_rule_id(&feedback.api),
            codec: ResponseBodyCodec::Docx,
            matching_cases: evidence.cases.len(),
            selected_difference_cases,
            residual_difference_cases: 0,
            discovered_unordered_paths: Vec::new(),
            discovered_unordered_joined_string_paths: Vec::new(),
            effective_unordered_paths: Vec::new(),
            effective_unordered_joined_string_paths: Vec::new(),
            discovered_docx_timestamps: discovered
                .into_iter()
                .map(|(part, element)| format!("{part}#{element}"))
                .collect(),
            effective_docx_timestamps: effective,
            offline_verification: None,
            order_only: None,
            changed,
            applied: false,
            diff,
        },
    })
}

fn selectors(rules: &[DocxTimestampRule]) -> BTreeSet<(String, String)> {
    rules
        .iter()
        .map(|rule| (rule.part.clone(), rule.element.clone()))
        .collect()
}
