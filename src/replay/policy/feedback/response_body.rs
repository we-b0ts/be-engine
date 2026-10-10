use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::super::config::{fingerprint, load_replay_policy};
use super::super::response::{
    DocxTimestampRule, Hessian2ResponseRules, ProtobufResponseRules, ResponseBodyCodec,
    ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath, parse_api, response_body_rule_id,
    validate_response_rules,
};
use super::document::{render_response_rules, replace_response_rules};
use super::evidence::{AggregateEvidence, AssertionEvidence};
use crate::replay::assertion::{RequestTimes, diagnose_response_body, read_replay_request_times};
use crate::replay::{
    ResponseAssertionCaseReport, ResponseBodyJoinedStringCandidate,
    ResponseBodyUnorderedPathCandidate, ResponseDifferenceKind, read_actual_response_body,
    read_expected_response_body,
};

mod codec;
mod docx_plan;
mod path;
mod plan_apply;

use codec::{
    compare_response_body, selected_response_body_paths_match, validate_unreported_codec_candidate,
};
use path::{
    BodyPath, display as body_path_display, from_candidate as body_path_from_candidate,
    from_difference as body_path_from_difference,
    from_joined_string_candidate as body_path_from_joined_string_candidate,
    from_joined_string_rule as body_path_from_joined_string_rule, from_rule as body_path_from_rule,
    into_candidate as candidate_from_body_path,
    into_joined_string_candidate as joined_string_candidate_from_body_path, joined_string_location,
};

#[derive(Debug, Clone)]
pub struct ResponseBodyRuleFeedback {
    pub policy_path: PathBuf,
    pub api: String,
    pub codec: ResponseBodyCodec,
    pub unordered_paths: Vec<ResponseBodyUnorderedPath>,
    pub unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    pub docx_timestamps: Vec<DocxTimestampRule>,
    pub evidence: ResponseBodyRuleEvidence,
}

#[derive(Debug, Clone)]
pub enum ResponseBodyRuleEvidence {
    FocusedE2e {
        assertion_report: PathBuf,
        aggregate_report: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyRuleEvidenceKind {
    FocusedE2e,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseBodyRuleVerificationOutcome {
    pub kind: ResponseBodyRuleEvidenceKind,
    pub complete: bool,
    pub passed: bool,
    pub cases: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseBodyRuleReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub evidence_kind: ResponseBodyRuleEvidenceKind,
    pub evidence_report: PathBuf,
    pub evidence_fingerprint: String,
    pub api: String,
    pub rule_id: String,
    pub codec: ResponseBodyCodec,
    pub matching_cases: usize,
    pub selected_difference_cases: usize,
    pub residual_difference_cases: usize,
    pub discovered_unordered_paths: Vec<ResponseBodyUnorderedPathCandidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_unordered_joined_string_paths: Vec<ResponseBodyJoinedStringCandidate>,
    pub effective_unordered_paths: Vec<ResponseBodyUnorderedPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_unordered_joined_string_paths: Vec<ResponseBodyJoinedStringPath>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_docx_timestamps: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_docx_timestamps: Vec<DocxTimestampRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_verification: Option<ResponseBodyRuleVerificationOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_only: Option<bool>,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

pub struct ResponseBodyRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    verification: ResponseBodyPlanVerification,
    report: ResponseBodyRuleReport,
}

enum ResponseBodyPlanVerification {
    FocusedE2e { cases: Vec<FocusedVerificationCase> },
}

struct FocusedVerificationCase {
    case_id: String,
    request: PathBuf,
    expected_response: PathBuf,
    actual_response: PathBuf,
}

struct ResponseBodyPlanningEvidence {
    kind: ResponseBodyRuleEvidenceKind,
    report: PathBuf,
    fingerprint: String,
    cases: Vec<ResponseBodyPlanningCase>,
    verification: ResponseBodyPlanVerification,
}

struct ResponseBodyPlanningCase {
    case_id: String,
    passed: bool,
    policy_mismatch_rule_ids: Vec<String>,
    response: Option<ResponseAssertionCaseReport>,
    expected_body: Vec<u8>,
    actual_body: Vec<u8>,
    times: RequestTimes,
}

fn load_planning_evidence(
    evidence: &ResponseBodyRuleEvidence,
    policy_fingerprint: &str,
    api: &str,
) -> Result<ResponseBodyPlanningEvidence> {
    match evidence {
        ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report,
            aggregate_report,
        } => load_focused_e2e_evidence(assertion_report, aggregate_report, policy_fingerprint, api),
    }
}

fn load_focused_e2e_evidence(
    assertion_report: &Path,
    aggregate_report: &Path,
    policy_fingerprint: &str,
    api: &str,
) -> Result<ResponseBodyPlanningEvidence> {
    let assertion_bytes = read_regular(assertion_report, "focused E2E assertion report")?;
    let assertion: AssertionEvidence =
        serde_json::from_slice(&assertion_bytes).context("invalid focused E2E assertion report")?;
    ensure!(
        assertion.version == 3
            && assertion.expected_response == "assertions_only"
            && assertion.assertion_mode == "runner_owned",
        "response-body rule planning requires current runner-owned focused E2E evidence"
    );
    ensure!(
        assertion.policy_fingerprint.as_deref() == Some(policy_fingerprint),
        "focused E2E replay policy fingerprint is stale"
    );
    let aggregate_bytes = read_regular(aggregate_report, "focused E2E aggregate report")?;
    let aggregate: AggregateEvidence =
        serde_json::from_slice(&aggregate_bytes).context("invalid focused E2E aggregate report")?;
    ensure!(
        aggregate.complete,
        "focused E2E aggregate evidence must be complete"
    );
    ensure!(
        aggregate.case_source == assertion.case_source,
        "focused E2E assertion and aggregate evidence use different case sources"
    );
    let assertion_case_ids = assertion
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let selected_case_ids = aggregate
        .selected_case_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        assertion_case_ids == selected_case_ids,
        "focused E2E assertion evidence does not cover the complete selected case set"
    );
    let (method, path_pattern) = parse_api(api)?;
    let mut cases = Vec::with_capacity(assertion.cases.len());
    let mut verification_cases = Vec::with_capacity(assertion.cases.len());
    for case in assertion.cases {
        let summary = case
            .response
            .with_context(|| format!("case {:?} has no response assertion", case.case_id))?;
        ensure!(
            summary.method.eq_ignore_ascii_case(method)
                && super::super::pattern::path_pattern_matches(path_pattern, &summary.path),
            "case {:?} belongs to another API",
            case.case_id
        );
        ensure!(
            summary.policy_fingerprint == policy_fingerprint,
            "case {:?} response assertion policy fingerprint is stale",
            case.case_id
        );
        let detail_report = summary
            .detail_report
            .as_ref()
            .with_context(|| format!("case {:?} has no assertion detail path", case.case_id))?;
        let detail_bytes = read_regular(detail_report, "focused E2E assertion detail")?;
        ensure!(
            summary.detail_fingerprint.as_deref() == Some(fingerprint(&detail_bytes).as_str()),
            "case {:?} assertion detail changed after publication",
            case.case_id
        );
        let detail: ResponseAssertionCaseReport = serde_json::from_slice(&detail_bytes)
            .context("invalid focused E2E assertion detail")?;
        ensure!(
            detail.version == 3
                && detail.case_id == case.case_id
                && detail.method == summary.method
                && detail.path == summary.path
                && detail.body_codec == summary.body_codec
                && detail.gateway_protocol
                    == summary
                        .gateway_protocol
                        .context("focused E2E response summary has no gateway protocol",)?
                && detail.policy_fingerprint == summary.policy_fingerprint
                && detail.differences.len() == summary.difference_count
                && detail.passed == case.passed,
            "case {:?} assertion detail does not match its published summary",
            case.case_id
        );
        let request = summary
            .request
            .clone()
            .with_context(|| format!("case {:?} has no request path", case.case_id))?;
        let expected_response = summary
            .expected_response
            .clone()
            .with_context(|| format!("case {:?} has no expected response path", case.case_id))?;
        let actual_response = summary
            .actual_response
            .clone()
            .with_context(|| format!("case {:?} has no actual response path", case.case_id))?;
        let (expected_body, actual_body) = if case.passed {
            (Vec::new(), Vec::new())
        } else {
            (
                read_expected_response_body(&expected_response, detail.gateway_protocol)?,
                read_actual_response_body(&actual_response, detail.gateway_protocol)?,
            )
        };
        let times = read_replay_request_times(&request, &actual_response)?;
        let policy_mismatch_rule_ids = detail
            .unused_applicable_generated_rule_ids
            .iter()
            .chain(&detail.unused_applicable_unordered_rule_ids)
            .chain(&detail.unused_applicable_unordered_joined_string_rule_ids)
            .chain(&detail.unused_applicable_body_rule_ids)
            .cloned()
            .collect();
        verification_cases.push(FocusedVerificationCase {
            case_id: case.case_id.clone(),
            request,
            expected_response,
            actual_response,
        });
        cases.push(ResponseBodyPlanningCase {
            case_id: case.case_id,
            passed: case.passed,
            policy_mismatch_rule_ids,
            response: Some(detail),
            expected_body,
            actual_body,
            times,
        });
    }
    ensure!(
        !cases.is_empty(),
        "focused E2E evidence contains no cases for {api}"
    );
    Ok(ResponseBodyPlanningEvidence {
        kind: ResponseBodyRuleEvidenceKind::FocusedE2e,
        report: assertion_report.to_path_buf(),
        fingerprint: fingerprint(&assertion_bytes),
        cases,
        verification: ResponseBodyPlanVerification::FocusedE2e {
            cases: verification_cases,
        },
    })
}

pub fn plan_response_body_rule(feedback: ResponseBodyRuleFeedback) -> Result<ResponseBodyRulePlan> {
    parse_api(&feedback.api)?;
    let original = read_regular_text(&feedback.policy_path, "replay policy")?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    ensure!(
        loaded.document.version >= 3,
        "typed response-body rules require replay policy version 3"
    );
    let evidence = load_planning_evidence(&feedback.evidence, &loaded.fingerprint, &feedback.api)?;

    let existing = loaded
        .document
        .response_rules
        .configured_response_body_rule(&feedback.api);
    if let Some(existing) = &existing {
        ensure!(
            existing.codec == feedback.codec,
            "response-body rule already uses a different codec"
        );
    }
    if feedback.codec == ResponseBodyCodec::Docx {
        return docx_plan::plan(feedback, original, loaded, evidence, existing);
    }
    ensure!(
        feedback.docx_timestamps.is_empty(),
        "protobuf and Hessian2 response-body rules cannot carry DOCX timestamps"
    );
    let codec_configured = existing.is_some();
    ensure!(
        feedback
            .unordered_paths
            .iter()
            .all(|path| path.codec() == feedback.codec),
        "response-body rule plan contains an unordered path for a different codec"
    );
    ensure!(
        feedback
            .unordered_joined_string_paths
            .iter()
            .all(|path| path.codec() == feedback.codec),
        "response-body rule plan contains a joined-string path for a different codec"
    );
    let matching = &evidence.cases;
    let mut diagnosed_difference_cases = 0;
    let mut discovered = BTreeSet::new();
    let mut discovered_joined_string = BTreeSet::<(BodyPath, String)>::new();
    let mut diagnostic_paths = BTreeSet::new();
    let mut diagnostic_joined_string_paths = BTreeSet::new();
    let mut case_candidates = Vec::new();
    for case in matching {
        ensure!(
            case.policy_mismatch_rule_ids.is_empty(),
            "case {:?} has an unused applicable response rule",
            case.case_id
        );
        if case.passed {
            continue;
        }
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
            "case {:?} has differences other than the response body value",
            case.case_id
        );
        if let Some(body) = response.body_diagnosis.as_ref() {
            let codec_reported = body.codec == feedback.codec
                || (!body.configured && body.codec_candidates.contains(&feedback.codec));
            if !codec_reported && !codec_configured && !body.configured {
                validate_unreported_codec_candidate(
                    &case.case_id,
                    feedback.codec,
                    &case.expected_body,
                    &case.actual_body,
                )?;
            } else {
                ensure!(
                    codec_reported,
                    "case {:?} does not support the requested response body codec",
                    case.case_id
                );
            }
        } else if !codec_configured {
            validate_unreported_codec_candidate(
                &case.case_id,
                feedback.codec,
                &case.expected_body,
                &case.actual_body,
            )?;
        } else {
            anyhow::bail!(
                "case {:?} was not evaluated with the configured response body codec",
                case.case_id
            );
        }
        let selected_diagnosis =
            diagnose_response_body(&case.expected_body, &case.actual_body, feedback.codec)
                .with_context(|| {
                    format!(
                        "case {:?} cannot be diagnosed with the selected response body codec",
                        case.case_id
                    )
                })?;
        diagnosed_difference_cases += 1;
        let case_unordered = selected_diagnosis
            .unordered_path_candidates
            .iter()
            .filter_map(|candidate| body_path_from_candidate(candidate, feedback.codec))
            .collect::<BTreeSet<_>>();
        let case_joined = selected_diagnosis
            .unordered_joined_string_candidates
            .iter()
            .filter_map(|candidate| {
                body_path_from_joined_string_candidate(candidate, feedback.codec)
                    .map(|path| (path, candidate.separator().to_string()))
            })
            .collect::<BTreeSet<_>>();
        let case_differences = selected_diagnosis
            .differences
            .iter()
            .filter_map(|difference| body_path_from_difference(difference, feedback.codec))
            .collect::<BTreeSet<_>>();
        let case_joined_differences = case_differences
            .iter()
            .cloned()
            .map(joined_string_location)
            .collect::<BTreeSet<_>>();
        discovered.extend(case_unordered.iter().cloned());
        discovered_joined_string.extend(case_joined.iter().cloned());
        diagnostic_paths.extend(case_differences.iter().cloned());
        diagnostic_joined_string_paths.extend(case_joined_differences.iter().cloned());
        case_candidates.push((
            case_unordered,
            case_joined,
            case_differences,
            case_joined_differences,
        ));
    }
    ensure!(
        diagnosed_difference_cases > 0,
        "response evidence contains no exact response-body difference"
    );
    let existing_fields = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_paths.iter())
        .map(body_path_from_rule)
        .collect::<BTreeSet<_>>();
    let existing_joined_string_fields = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_joined_string_paths.iter())
        .map(body_path_from_joined_string_rule)
        .collect::<BTreeSet<_>>();
    let new_discovered = discovered
        .difference(&existing_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    let selectable_unordered = new_discovered
        .union(&diagnostic_paths)
        .filter(|path| !existing_fields.contains(*path))
        .cloned()
        .collect::<BTreeSet<_>>();
    let selectable_joined_string = diagnostic_joined_string_paths
        .difference(&existing_joined_string_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    let selecting_paths =
        !feedback.unordered_paths.is_empty() || !feedback.unordered_joined_string_paths.is_empty();
    let requested = feedback
        .unordered_paths
        .iter()
        .map(body_path_from_rule)
        .collect::<BTreeSet<_>>();
    let requested_joined_string = feedback
        .unordered_joined_string_paths
        .iter()
        .map(body_path_from_joined_string_rule)
        .collect::<BTreeSet<_>>();
    let requested_joined_candidates = feedback
        .unordered_joined_string_paths
        .iter()
        .map(|path| {
            (
                body_path_from_joined_string_rule(path),
                path.separator().to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    if codec_configured || selecting_paths {
        ensure!(
            requested.len() == feedback.unordered_paths.len(),
            "response-body rule plan repeats an unordered body path"
        );
        ensure!(
            requested_joined_string.len() == feedback.unordered_joined_string_paths.len(),
            "response-body rule plan repeats a joined-string body path"
        );
        ensure!(
            !requested.is_empty() || !requested_joined_string.is_empty(),
            "an existing response-body codec rule requires at least one newly reviewed unordered or joined-string path"
        );
        ensure!(
            requested.is_disjoint(&existing_fields),
            "response-body rule plan repeats a body path already present in the rule"
        );
        ensure!(
            requested_joined_string.is_disjoint(&existing_joined_string_fields),
            "response-body rule plan repeats a joined-string body path already present in the rule"
        );
        ensure!(
            requested.is_disjoint(&requested_joined_string),
            "response-body rule plan uses the same body path as both an unordered collection and a joined-string path"
        );
        let unsupported = requested
            .difference(&selectable_unordered)
            .map(body_path_display)
            .collect::<Vec<_>>();
        ensure!(
            unsupported.is_empty(),
            "reviewed unordered body paths were not present in typed response differences: {}",
            unsupported.join(", ")
        );
        let unsupported_joined = requested_joined_string
            .difference(&selectable_joined_string)
            .map(body_path_display)
            .collect::<Vec<_>>();
        ensure!(
            unsupported_joined.is_empty(),
            "reviewed joined-string body paths were not present in typed response differences: {}",
            unsupported_joined.join(", ")
        );
    }

    let selected_difference_cases = if selecting_paths {
        case_candidates
            .iter()
            .filter(|(unordered, joined, differences, joined_differences)| {
                !unordered.is_disjoint(&requested)
                    || !differences.is_disjoint(&requested)
                    || joined
                        .iter()
                        .any(|candidate| requested_joined_candidates.contains(candidate))
                    || !joined_differences.is_disjoint(&requested_joined_string)
            })
            .count()
    } else {
        diagnosed_difference_cases
    };

    let mut effective_paths = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_paths.iter().cloned())
        .map(|path| (body_path_from_rule(&path), path))
        .collect::<BTreeMap<_, _>>();
    effective_paths.extend(
        feedback
            .unordered_paths
            .iter()
            .cloned()
            .map(|path| (body_path_from_rule(&path), path)),
    );
    let effective_paths = effective_paths.into_values().collect::<Vec<_>>();
    let mut effective_joined_string_paths = existing
        .as_ref()
        .into_iter()
        .flat_map(|rule| rule.unordered_joined_string_paths.iter().cloned())
        .map(|path| (body_path_from_joined_string_rule(&path), path))
        .collect::<BTreeMap<_, _>>();
    effective_joined_string_paths.extend(
        feedback
            .unordered_joined_string_paths
            .iter()
            .cloned()
            .map(|path| (body_path_from_joined_string_rule(&path), path)),
    );
    let effective_joined_string_paths = effective_joined_string_paths
        .into_values()
        .collect::<Vec<_>>();
    let mut residual_difference_cases = 0;
    if !effective_paths.is_empty() || !effective_joined_string_paths.is_empty() {
        for case in matching.iter().filter(|case| !case.passed) {
            if selecting_paths {
                let selected_matches_before = selected_response_body_paths_match(
                    &case.expected_body,
                    &case.actual_body,
                    feedback.codec,
                    &effective_paths,
                    &effective_joined_string_paths,
                    &feedback.unordered_paths,
                    &feedback.unordered_joined_string_paths,
                )?;
                ensure!(
                    selected_matches_before,
                    "reviewed response-body unordered paths do not preserve exact values at their selected locations in case {:?}",
                    case.case_id
                );
            }
            let matches_before = compare_response_body(
                &case.expected_body,
                &case.actual_body,
                feedback.codec,
                &effective_paths,
                &effective_joined_string_paths,
            )?;
            residual_difference_cases += usize::from(!matches_before);
        }
    } else {
        residual_difference_cases = diagnosed_difference_cases;
    }
    match feedback.codec {
        ResponseBodyCodec::Protobuf => {
            let unordered = effective_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyUnorderedPath::Protobuf(path) => Ok(path.clone()),
                    ResponseBodyUnorderedPath::Hessian2(_) => {
                        anyhow::bail!("protobuf rule contains a Hessian2 unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let unordered_joined_string = effective_joined_string_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyJoinedStringPath::Protobuf(path) => Ok(path.clone()),
                    ResponseBodyJoinedStringPath::Hessian2(_) => {
                        anyhow::bail!("protobuf rule contains a Hessian2 joined-string path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            loaded.document.response_rules.protobuf.insert(
                feedback.api.clone(),
                ProtobufResponseRules {
                    unordered,
                    unordered_joined_string,
                },
            );
        }
        ResponseBodyCodec::Hessian2 => {
            let unordered = effective_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyUnorderedPath::Hessian2(path) => Ok(path.clone()),
                    ResponseBodyUnorderedPath::Protobuf(_) => {
                        anyhow::bail!("Hessian2 rule contains a protobuf unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            let unordered_joined_string = effective_joined_string_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyJoinedStringPath::Hessian2(path) => Ok(path.clone()),
                    ResponseBodyJoinedStringPath::Protobuf(_) => {
                        anyhow::bail!("Hessian2 rule contains a protobuf joined-string path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            loaded.document.response_rules.hessian2.insert(
                feedback.api.clone(),
                Hessian2ResponseRules {
                    unordered,
                    unordered_joined_string,
                },
            );
        }
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
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

    let matching_cases = matching.len();
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
            codec: feedback.codec,
            matching_cases,
            selected_difference_cases,
            residual_difference_cases,
            discovered_unordered_paths: discovered
                .into_iter()
                .map(candidate_from_body_path)
                .collect(),
            discovered_unordered_joined_string_paths: discovered_joined_string
                .into_iter()
                .map(|(path, separator)| joined_string_candidate_from_body_path(path, separator))
                .collect(),
            effective_unordered_paths: effective_paths,
            effective_unordered_joined_string_paths: effective_joined_string_paths,
            discovered_docx_timestamps: Vec::new(),
            effective_docx_timestamps: Vec::new(),
            offline_verification: None,
            order_only: None,
            changed,
            applied: false,
            diff,
        },
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

fn read_regular_text(path: &Path, label: &str) -> Result<String> {
    String::from_utf8(read_regular(path, label)?)
        .with_context(|| format!("{label} {} is not UTF-8", path.display()))
}
