use super::response::response_locations_overlap;
mod http_cross_case;
pub use http_cross_case::{
    HttpCrossCaseFeedback, HttpCrossCasePlan, HttpCrossCaseReport, plan_http_cross_case,
};
mod document;
pub(crate) use document::replace_request_rule_section;
mod evidence;
mod justification;
mod memcached;
mod mysql_time;
pub use mysql_time::{
    MysqlTimeRuleFeedback, MysqlTimeRulePlan, MysqlTimeRuleReport, MysqlTimeSelector,
    MysqlTimeValueSelector, plan_mysql_time_rule,
};
mod generated_values;
mod model;
mod response_body;
mod time_plan;
pub use generated_values::{
    DynamicValueMysqlTimeRule, DynamicValueRedisTimeRule, DynamicValueRuleFeedback,
    GeneratedValueRulePlan, GeneratedValueRuleReport, RedisJsonTimeValueSelector,
    ResponseHeaderDateRuleFeedback, plan_dynamic_value_mysql_time_rule,
    plan_dynamic_value_redis_time_rule, plan_dynamic_value_rule, plan_response_header_date_rule,
};

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use self::document::{render_response_rules, replace_response_rules};
use self::evidence::{
    AggregateEvidence, AssertionCaseEvidence, AssertionEvidence, difference_supports_rule,
    response_rule_exists,
};
use super::config::{LoadedReplayPolicy, fingerprint, load_replay_policy};
use super::pattern::path_pattern_matches;
use super::response::{
    GeneratedResponseRule, JsonJoinedStringResponseRule, JsonUnorderedResponseRule,
    ResponseRuleKind, parse_api, response_rule_id, validate_json_pointer, validate_response_rules,
};
use crate::config::edit::write_atomic;

use justification::ResponseRuleJustification;
pub use memcached::{
    MemcachedTimestampRuleFeedback, MemcachedTimestampRulePlan, MemcachedTimestampRuleReport,
    plan_memcached_timestamp_rule,
};
pub use model::{ResponseRuleFeedback, ResponseRuleReport};
pub use response_body::{
    ResponseBodyRuleEvidence, ResponseBodyRuleEvidenceKind, ResponseBodyRuleFeedback,
    ResponseBodyRulePlan, ResponseBodyRuleReport, ResponseBodyRuleVerificationOutcome,
    plan_response_body_rule,
};

pub struct ResponseRulePlan {
    policy_path: PathBuf,
    original: String,
    updated: String,
    report: ResponseRuleReport,
    witnesses: Vec<(PathBuf, String)>,
}

impl ResponseRulePlan {
    pub(crate) fn time_evidence_witnesses(&self) -> Vec<(PathBuf, String)> {
        self.witnesses.clone()
    }
    pub fn report(&self) -> &ResponseRuleReport {
        &self.report
    }

    pub fn apply(self) -> Result<ResponseRuleReport> {
        crate::policy::retired_authoring()?;
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
        for (path, identity) in &self.witnesses {
            ensure!(
                fingerprint(&read_published_report(path, "response time evidence")?) == *identity,
                "response time evidence changed after planning; rerun plan"
            );
        }
        if self.report.changed {
            write_atomic(&self.policy_path, self.updated.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_response_rule(feedback: ResponseRuleFeedback) -> Result<ResponseRulePlan> {
    crate::policy::retired_authoring()?;
    ensure!(
        feedback.kind != ResponseRuleKind::Jwt,
        "JWT responses require the typed response-jwt planner"
    );
    let justification = justification::validate(
        feedback.kind,
        feedback.time,
        feedback.source_evidence,
        feedback.source_example,
        feedback.target_example,
        feedback.separator,
    )?;
    let prepared = prepare_response_rule(
        &feedback.policy_path,
        &feedback.api,
        &feedback.json_pointers,
    )?;
    let assertion_bytes = read_regular(&feedback.assertion_report, "assertion report")?;
    let mut assertions: AssertionEvidence =
        serde_json::from_slice(&assertion_bytes).context("invalid assertion report")?;
    let detail_witnesses = assertions
        .cases
        .iter()
        .filter_map(|case| {
            let response = case.response.as_ref()?;
            Some((
                response.detail_report.clone()?,
                response.detail_fingerprint.clone()?,
            ))
        })
        .collect::<Vec<_>>();
    hydrate_assertion_details(&mut assertions)?;
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
        justification.separator.as_deref(),
    )?;
    let mut witnesses = if let Some(time) = justification.time {
        time_plan::verify(&feedback.api, &feedback.json_pointers, &assertions, time)?
    } else {
        Vec::new()
    };
    if justification.time.is_some() {
        witnesses.extend(detail_witnesses);
        witnesses.push((
            feedback.assertion_report.clone(),
            fingerprint(&assertion_bytes),
        ));
        witnesses.push((
            feedback.aggregate_report.clone(),
            fingerprint(&aggregate_bytes),
        ));
    }
    let mut plan = build_response_rule_plan(
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
    )?;
    plan.witnesses = witnesses;
    Ok(plan)
}

fn hydrate_assertion_details(assertions: &mut AssertionEvidence) -> Result<()> {
    for case in &mut assertions.cases {
        let Some(response) = &mut case.response else {
            continue;
        };
        let Some(detail_report) = response.detail_report.take() else {
            continue;
        };
        let expected_fingerprint = response
            .detail_fingerprint
            .take()
            .context("assertion summary has no detail fingerprint")?;
        let detail_bytes = read_published_report(&detail_report, "assertion detail report")?;
        ensure!(
            fingerprint(&detail_bytes) == expected_fingerprint,
            "assertion detail report fingerprint changed: {}",
            detail_report.display()
        );
        let detail = serde_json::from_slice::<self::evidence::ResponseCaseEvidence>(&detail_bytes)
            .with_context(|| {
                format!(
                    "invalid assertion detail report {}",
                    detail_report.display()
                )
            })?;
        ensure!(
            !detail.method.is_empty()
                && !detail.path.is_empty()
                && detail.body_codec != super::response::ResponseBodyCodec::Unknown
                && detail.detail_report.is_none()
                && detail.detail_fingerprint.is_none(),
            "assertion detail report is incomplete: {}",
            detail_report.display()
        );
        *response = detail;
    }
    Ok(())
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
        loaded.document.version >= 3,
        "response rules require replay policy version 3"
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
    separator: Option<&str>,
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
    let mut residual_difference_cases = 0;
    let mut unselected_difference_pointers = BTreeSet::new();
    for (case, response) in &matching {
        ensure!(
            case.policy_mismatch_rule_ids.is_empty(),
            "case {:?} has unused applicable response rules",
            case.case_id
        );
        ensure!(
            response.body_codec == super::response::ResponseBodyCodec::Json,
            "response rules require structural JSON assertion evidence"
        );
        let mut case_has_selected_difference = false;
        let mut case_has_unselected_difference = false;
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
                ensure!(
                    kind != ResponseRuleKind::UnorderedJoinedString
                        || response.has_candidate(kind, &difference.pointer, separator),
                    "case {:?} does not provide joined-string evidence for {}",
                    case.case_id,
                    difference.pointer
                );
                observed_difference = true;
                case_has_selected_difference = true;
            } else {
                unselected_difference_pointers.insert(difference.pointer.clone());
                case_has_unselected_difference = true;
            }
        }
        selected_difference_cases += usize::from(case_has_selected_difference);
        residual_difference_cases += usize::from(case_has_unselected_difference);
        for pointer in &prepared.requested {
            let has_overlapping_difference = response
                .differences
                .iter()
                .any(|difference| response_locations_overlap(pointer, &difference.pointer));
            ensure!(
                response.has_candidate(kind, pointer, separator)
                    || response
                        .applied_rule_ids(kind)
                        .contains(&response_rule_id(kind, api, pointer))
                    || !has_overlapping_difference
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
                response_rule_exists(
                    &prepared.loaded.document.response_rules,
                    kind,
                    api,
                    pointer,
                    separator,
                )
            }),
        "response evidence contains no differing field selected by the proposed rule"
    );
    Ok(ResponseEvidenceValidation {
        matching_cases: matching.len(),
        selected_difference_cases,
        residual_difference_cases,
        unselected_difference_pointers: unselected_difference_pointers.into_iter().collect(),
    })
}

struct ResponseEvidenceValidation {
    matching_cases: usize,
    selected_difference_cases: usize,
    residual_difference_cases: usize,
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
    let api_rules = updated_rules.json.entry(api.clone()).or_default();
    let before = match kind {
        kind if kind.is_generated() => api_rules
            .generated_for_kind(kind)
            .expect("generated kind has a rule collection")
            .iter()
            .map(|field| field.pointer.clone())
            .collect::<BTreeSet<_>>(),
        ResponseRuleKind::Unordered => api_rules
            .unordered
            .iter()
            .map(|field| field.pointer.clone())
            .collect::<BTreeSet<_>>(),
        ResponseRuleKind::UnorderedJoinedString => api_rules
            .unordered_joined_string
            .iter()
            .map(|field| field.pointer.clone())
            .collect::<BTreeSet<_>>(),
        _ => unreachable!("all response rule kinds are covered"),
    };
    match kind {
        kind if kind.is_generated() => {
            let fields = api_rules
                .generated_for_kind_mut(kind)
                .expect("generated kind has a rule collection");
            for pointer in &prepared.requested {
                let proposed = GeneratedResponseRule {
                    time: justification
                        .time
                        .and_then(super::response::ResponseTimeRule::timestamp_mode)
                        .filter(|mode| {
                            *mode != super::response::ResponseTimestampMode::RequestWindow
                        }),
                    unit: justification
                        .time
                        .and_then(super::response::ResponseTimeRule::unit),
                    format: justification
                        .time
                        .and_then(super::response::ResponseTimeRule::format),
                    pointer: pointer.clone(),
                    source_evidence: justification
                        .source_evidence
                        .clone()
                        .expect("generated justification requires source evidence"),
                    source_example: justification
                        .source_example
                        .clone()
                        .expect("generated justification requires a source example"),
                    target_example: justification
                        .target_example
                        .clone()
                        .expect("generated justification requires a target example"),
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
            let fields = &mut api_rules.unordered;
            for pointer in &prepared.requested {
                let proposed = JsonUnorderedResponseRule {
                    pointer: pointer.clone(),
                    source_evidence: justification
                        .source_evidence
                        .clone()
                        .expect("unordered justification requires source evidence"),
                };
                if let Some(existing) = fields.iter_mut().find(|field| field.pointer == *pointer) {
                    *existing = proposed;
                } else {
                    fields.push(proposed);
                }
            }
            fields.sort_by(|left, right| left.pointer.cmp(&right.pointer));
        }
        ResponseRuleKind::UnorderedJoinedString => {
            let fields = &mut api_rules.unordered_joined_string;
            for pointer in &prepared.requested {
                let proposed = JsonJoinedStringResponseRule {
                    pointer: pointer.clone(),
                    separator: justification
                        .separator
                        .clone()
                        .expect("joined-string justification requires a separator"),
                    source_evidence: justification
                        .source_evidence
                        .clone()
                        .expect("joined-string justification requires source evidence"),
                };
                if let Some(existing) = fields.iter_mut().find(|field| field.pointer == *pointer) {
                    *existing = proposed;
                } else {
                    fields.push(proposed);
                }
            }
            fields.sort_by(|left, right| left.pointer.cmp(&right.pointer));
        }
        _ => unreachable!("all response rule kinds are covered"),
    }
    validate_response_rules(&updated_rules)?;
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
            Some(aggregate_dirty),
        ),
    };
    Ok(ResponseRulePlan {
        witnesses: Vec::new(),
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
            kind,
            time: justification.time,
            api,
            json_pointers: prepared.requested.into_iter().collect(),
            source_evidence: justification.source_evidence,
            source_example: justification.source_example,
            target_example: justification.target_example,
            separator: justification.separator,
            matching_cases: response_evidence.matching_cases,
            selected_difference_cases: response_evidence.selected_difference_cases,
            residual_difference_cases: response_evidence.residual_difference_cases,
            unselected_difference_pointers: response_evidence.unselected_difference_pointers,
            aggregate_dirty,
            changed,
            applied: false,
            added_rule_ids: added,
            diff,
        },
    })
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    read_regular_at(path, path, label)
}

pub(in crate::replay::policy) fn read_published_report(
    path: &Path,
    label: &str,
) -> Result<Vec<u8>> {
    if crate::dependency_index::scoped::view_path(path).is_some() {
        return crate::dependency_index::scoped::read_bytes(path);
    }
    let resolved = resolve_published_report_path(path);
    read_regular_at(&resolved, path, label)
}

fn read_regular_at(resolved: &Path, reported: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(resolved)
        .with_context(|| format!("failed to inspect {label} {}", reported.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    fs::read(resolved).with_context(|| format!("failed to read {label} {}", reported.display()))
}

/// Resolve a report path that may carry a stale `.active` segment left over from a
/// finalized E2E attempt. Older publishes wrote assertion-detail paths anchored at the
/// focused API `.active` directory; after publish renamed that directory to `latest`,
/// the inner paths dangled. Fall back to the `latest` sibling so existing response-rule
/// evidence remains hydratable without a fresh E2E attempt.
fn resolve_published_report_path(path: &Path) -> PathBuf {
    match fs::symlink_metadata(path) {
        Ok(_) => return path.to_path_buf(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return path.to_path_buf(),
    }
    let Some(active_dir) = path
        .ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new(".active")))
    else {
        return path.to_path_buf();
    };
    let Ok(relative) = path.strip_prefix(active_dir) else {
        return path.to_path_buf();
    };
    let candidate = active_dir.with_file_name("latest").join(relative);
    if fs::symlink_metadata(&candidate).is_ok() {
        candidate
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
#[path = "feedback/path_tests.rs"]
mod path_tests;
#[cfg(test)]
#[path = "feedback/tests.rs"]
mod tests;

mod redis_cross_case;
pub use redis_cross_case::{
    RedisCrossCaseFeedback, RedisCrossCasePlan, RedisCrossCaseReport, plan_redis_cross_case,
};

pub use generated_values::{DependencyRequestRuleFeedback, plan_dependency_request_rule};

pub use generated_values::{ResponseJwtRuleFeedback, plan_response_jwt_rule};
