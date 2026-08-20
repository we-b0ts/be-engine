use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use super::representative::{
    ComparisonRepresentativeDifference, ComparisonRepresentativePolicyMismatch,
};
use crate::config::edit::{create_atomic, write_atomic};
use crate::replay::{
    ComparisonResponseAssertionOptions, ComparisonSourceMatch, ResponseAssertionCaseReport,
    assert_comparison_response, response_locations_overlap, validate_replay_policy,
};

const RUN_SUMMARY_FILE: &str = "comparison-recording-run.json";

#[derive(Debug, Clone)]
pub struct ComparisonVerificationOptions {
    pub case_source: PathBuf,
    pub policy: PathBuf,
    pub report: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComparisonVerificationCounts {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub policy_mismatch: usize,
    pub unevaluable: usize,
    pub source_changed_cases: usize,
    pub apis_total: usize,
    pub apis_passed: usize,
    pub apis_failed: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComparisonVerificationApiCounts {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub policy_mismatch: usize,
    pub unevaluable: usize,
    pub source_changed_cases: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonVerificationApi {
    pub passed: bool,
    pub counts: ComparisonVerificationApiCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerificationClassification {
    Passed,
    CandidateDifference,
    SourceChange,
    PolicyMismatch,
    Unevaluable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedSourceObservation {
    Before,
    After,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonVerificationCase {
    pub case_id: String,
    pub case_dir: String,
    pub api: String,
    pub classification: ComparisonVerificationClassification,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseAssertionCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_recheck: Option<ResponseAssertionCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_after: Option<ResponseAssertionCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_source: Option<MatchedSourceObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_change_pointers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_only_pointers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_mismatch_rule_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonVerificationReport {
    pub version: u8,
    pub kind: String,
    pub case_source: String,
    pub recording_summary_path: String,
    pub recording_summary_fingerprint: String,
    pub expected_response: String,
    pub assertion_mode: String,
    pub baseline_recheck: String,
    #[serde(default)]
    pub source_match: ComparisonSourceMatch,
    pub policy_path: String,
    pub policy_fingerprint: String,
    pub report_path: String,
    pub complete: bool,
    pub passed: bool,
    pub counts: ComparisonVerificationCounts,
    pub apis: std::collections::BTreeMap<String, ComparisonVerificationApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_difference: Option<ComparisonRepresentativeDifference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_policy_mismatch: Option<ComparisonRepresentativePolicyMismatch>,
    pub cases: Vec<ComparisonVerificationCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonVerificationOutcome {
    pub report_path: String,
    pub complete: bool,
    pub passed: bool,
    pub counts: ComparisonVerificationCounts,
    pub apis: std::collections::BTreeMap<String, ComparisonVerificationApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_difference: Option<ComparisonRepresentativeDifference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representative_policy_mismatch: Option<ComparisonRepresentativePolicyMismatch>,
}

impl ComparisonVerificationReport {
    pub fn outcome(&self) -> ComparisonVerificationOutcome {
        ComparisonVerificationOutcome {
            report_path: self.report_path.clone(),
            complete: self.complete,
            passed: self.passed,
            counts: self.counts.clone(),
            apis: self.apis.clone(),
            representative_difference: self.representative_difference.clone(),
            representative_policy_mismatch: self.representative_policy_mismatch.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RecordingSummary {
    status: String,
    ready: bool,
    finished_at: Option<serde_json::Value>,
    counts: RecordingCounts,
}

#[derive(Debug, Deserialize)]
struct RecordingCounts {
    published: usize,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    method: String,
    api_pattern: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseKind {
    version: u8,
    kind: String,
}

pub fn verify_comparison_recording(
    options: ComparisonVerificationOptions,
) -> Result<ComparisonVerificationReport> {
    let case_source = options.case_source.canonicalize().with_context(|| {
        format!(
            "failed to resolve comparison recording source {}",
            options.case_source.display()
        )
    })?;
    ensure!(
        case_source.is_dir(),
        "comparison recording source must be a directory"
    );
    let summary_path = case_source.join(RUN_SUMMARY_FILE);
    let summary_bytes = read_regular(&summary_path, "comparison recording summary")?;
    let summary: RecordingSummary = serde_json::from_slice(&summary_bytes)
        .with_context(|| format!("invalid recording summary {}", summary_path.display()))?;
    ensure!(
        summary.status == "completed" && summary.finished_at.is_some(),
        "comparison recording run is not finalized successfully"
    );
    ensure!(
        summary.ready,
        "comparison recording run never observed both upstreams ready"
    );

    let policy = validate_replay_policy(&options.policy)?;
    ensure!(
        policy.runner_owned_response_assertions,
        "comparison verification requires replay policy version 3"
    );
    let mut case_dirs = discover_cases(&case_source)?;
    case_dirs.sort();
    ensure!(
        !case_dirs.is_empty(),
        "comparison recording run contains no published cases"
    );
    ensure!(
        case_dirs.len() == summary.counts.published,
        "comparison recording summary reports {} published cases but {} were discovered",
        summary.counts.published,
        case_dirs.len()
    );

    let mut ids = BTreeSet::new();
    let mut cases = Vec::with_capacity(case_dirs.len());
    let mut api_counts =
        std::collections::BTreeMap::<String, ComparisonVerificationApiCounts>::new();
    let mut counts = ComparisonVerificationCounts {
        total: case_dirs.len(),
        ..ComparisonVerificationCounts::default()
    };
    for case_dir in case_dirs {
        let case_id = case_dir
            .file_name()
            .and_then(|name| name.to_str())
            .context("comparison recording case directory has no UTF-8 name")?
            .to_string();
        ensure!(
            ids.insert(case_id.clone()),
            "duplicate comparison recording case id {case_id:?}"
        );
        let request_path = case_dir.join("request.json");
        let request: RecordedRequest =
            serde_json::from_slice(&read_regular(&request_path, "comparison request")?)
                .with_context(|| {
                    format!("invalid comparison request {}", request_path.display())
                })?;
        let api = format!("{} {}", request.method, request.api_pattern)
            .parse::<crate::recording_api::RecordingApi>()
            .with_context(|| {
                format!(
                    "invalid comparison API metadata in {}",
                    request_path.display()
                )
            })?
            .to_string();
        let response = assert_comparison_response(ComparisonResponseAssertionOptions {
            case_id: case_id.clone(),
            request: request_path,
            expected_response: case_dir.join("expected-response.json"),
            response: case_dir.join("response.json"),
            policy: options.policy.clone(),
        });
        let recheck_path = case_dir.join("expected-response-after.json");
        let has_recheck = path_is_present(&recheck_path)?;
        let baseline_recheck = if has_recheck {
            Some(assert_comparison_response(
                ComparisonResponseAssertionOptions {
                    case_id: case_id.clone(),
                    request: case_dir.join("request.json"),
                    expected_response: case_dir.join("expected-response.json"),
                    response: recheck_path.clone(),
                    policy: options.policy.clone(),
                },
            ))
        } else {
            None
        };
        let response_after = match policy.comparison.source_match {
            ComparisonSourceMatch::Before => Ok(None),
            ComparisonSourceMatch::BeforeOrAfter if has_recheck => {
                assert_comparison_response(ComparisonResponseAssertionOptions {
                    case_id: case_id.clone(),
                    request: case_dir.join("request.json"),
                    expected_response: recheck_path,
                    response: case_dir.join("response.json"),
                    policy: options.policy.clone(),
                })
                .map(Some)
            }
            ComparisonSourceMatch::BeforeOrAfter => Err(anyhow!(
                "response_settings.comparison.source_match=before_or_after requires expected-response-after.json"
            )),
        };
        match (response, baseline_recheck.transpose(), response_after) {
            (Ok(response), Ok(baseline_recheck), Ok(response_after)) => {
                let source_change_pointers = baseline_recheck
                    .as_ref()
                    .map(difference_pointers)
                    .unwrap_or_default();
                let candidate_only_pointers =
                    unexplained_candidate_pointers(&response, baseline_recheck.as_ref());
                let policy_mismatch_rule_ids = policy_mismatch_rule_ids(
                    &response,
                    baseline_recheck.as_ref(),
                    response_after.as_ref(),
                );
                let matched_source = if response.differences.is_empty() {
                    Some(MatchedSourceObservation::Before)
                } else if response_after
                    .as_ref()
                    .is_some_and(|report| report.differences.is_empty())
                {
                    Some(MatchedSourceObservation::After)
                } else {
                    None
                };
                let api_entry = api_counts.entry(api.clone()).or_default();
                if !source_change_pointers.is_empty() {
                    counts.source_changed_cases += 1;
                    api_entry.source_changed_cases += 1;
                }
                if !policy_mismatch_rule_ids.is_empty() {
                    counts.policy_mismatch += 1;
                    api_entry.policy_mismatch += 1;
                }
                let (classification, passed) = if matched_source.is_some()
                    && !policy_mismatch_rule_ids.is_empty()
                {
                    (ComparisonVerificationClassification::PolicyMismatch, false)
                } else if matched_source.is_some() {
                    counts.passed += 1;
                    (ComparisonVerificationClassification::Passed, true)
                } else if candidate_only_pointers.is_empty() && !source_change_pointers.is_empty() {
                    counts.inconclusive += 1;
                    (ComparisonVerificationClassification::SourceChange, false)
                } else {
                    counts.failed += 1;
                    (
                        ComparisonVerificationClassification::CandidateDifference,
                        false,
                    )
                };
                update_api_counts(api_entry, classification);
                cases.push(ComparisonVerificationCase {
                    case_id,
                    case_dir: case_dir.display().to_string(),
                    api,
                    classification,
                    passed,
                    response: Some(response),
                    baseline_recheck,
                    response_after,
                    matched_source,
                    source_change_pointers,
                    candidate_only_pointers,
                    policy_mismatch_rule_ids,
                    error: None,
                });
            }
            (response, baseline_recheck, response_after) => {
                counts.unevaluable += 1;
                update_api_counts(
                    api_counts.entry(api.clone()).or_default(),
                    ComparisonVerificationClassification::Unevaluable,
                );
                let error = response
                    .err()
                    .into_iter()
                    .chain(baseline_recheck.err())
                    .chain(response_after.err())
                    .map(|error| format!("{error:#}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                cases.push(ComparisonVerificationCase {
                    case_id,
                    case_dir: case_dir.display().to_string(),
                    api,
                    classification: ComparisonVerificationClassification::Unevaluable,
                    passed: false,
                    response: None,
                    baseline_recheck: None,
                    response_after: None,
                    matched_source: None,
                    source_change_pointers: Vec::new(),
                    candidate_only_pointers: Vec::new(),
                    policy_mismatch_rule_ids: Vec::new(),
                    error: Some(error),
                });
            }
        }
    }
    let apis = api_counts
        .into_iter()
        .map(|(api, counts)| {
            let passed = counts.total > 0 && counts.passed == counts.total;
            (api, ComparisonVerificationApi { passed, counts })
        })
        .collect::<BTreeMap<_, _>>();
    counts.apis_total = apis.len();
    counts.apis_passed = apis.values().filter(|api| api.passed).count();
    counts.apis_failed = counts.apis_total.saturating_sub(counts.apis_passed);
    let representative_difference = super::representative::difference(&cases)?;
    let representative_policy_mismatch = super::representative::policy_mismatch(&cases);
    let complete = counts.unevaluable == 0;
    let passed = complete
        && counts.failed == 0
        && counts.passed == counts.total
        && apis.values().all(|api| api.passed);
    let report = ComparisonVerificationReport {
        version: 5,
        kind: "comparison_recording_verification".to_string(),
        case_source: case_source.display().to_string(),
        recording_summary_path: summary_path.display().to_string(),
        recording_summary_fingerprint: fingerprint(&summary_bytes),
        expected_response: "assertions_only".to_string(),
        assertion_mode: "comparison_recording".to_string(),
        baseline_recheck: "optional_source_consistency".to_string(),
        source_match: policy.comparison.source_match,
        policy_path: policy.path,
        policy_fingerprint: policy.fingerprint,
        report_path: options.report.display().to_string(),
        complete,
        passed,
        counts,
        apis,
        representative_difference,
        representative_policy_mismatch,
        cases,
    };
    write_report(&options.report, &report)?;
    Ok(report)
}

pub(crate) fn resolve_comparison_case_dir(case_source: &Path, case_id: &str) -> Result<PathBuf> {
    let case_source = case_source.canonicalize().with_context(|| {
        format!(
            "failed to resolve comparison recording source {}",
            case_source.display()
        )
    })?;
    let cases = discover_cases(&case_source)?;
    let mut matches = cases.into_iter().filter(|case| {
        case.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == case_id)
    });
    let case = matches.next().with_context(|| {
        format!(
            "comparison case {case_id:?} is not part of case source {}",
            case_source.display()
        )
    })?;
    ensure!(
        matches.next().is_none(),
        "duplicate comparison recording case id {case_id:?}"
    );
    Ok(case)
}

fn update_api_counts(
    counts: &mut ComparisonVerificationApiCounts,
    classification: ComparisonVerificationClassification,
) {
    counts.total += 1;
    match classification {
        ComparisonVerificationClassification::Passed => counts.passed += 1,
        ComparisonVerificationClassification::CandidateDifference => counts.failed += 1,
        ComparisonVerificationClassification::SourceChange => counts.inconclusive += 1,
        ComparisonVerificationClassification::PolicyMismatch => {}
        ComparisonVerificationClassification::Unevaluable => counts.unevaluable += 1,
    }
}

fn difference_pointers(report: &ResponseAssertionCaseReport) -> Vec<String> {
    report
        .differences
        .iter()
        .map(|difference| difference.pointer.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unexplained_candidate_pointers(
    response: &ResponseAssertionCaseReport,
    baseline_recheck: Option<&ResponseAssertionCaseReport>,
) -> Vec<String> {
    let source_differences = baseline_recheck
        .map(|report| report.differences.as_slice())
        .unwrap_or_default();
    response
        .differences
        .iter()
        .filter(|candidate| {
            !source_differences
                .iter()
                .any(|source| response_locations_overlap(&candidate.pointer, &source.pointer))
        })
        .map(|difference| difference.pointer.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn policy_mismatch_rule_ids(
    response: &ResponseAssertionCaseReport,
    baseline_recheck: Option<&ResponseAssertionCaseReport>,
    response_after: Option<&ResponseAssertionCaseReport>,
) -> Vec<String> {
    let reports = [Some(response), baseline_recheck, response_after]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let applied = reports
        .iter()
        .flat_map(|report| {
            report
                .applied_dynamic_rule_ids
                .iter()
                .chain(&report.applied_unordered_rule_ids)
                .chain(&report.applied_counter_rule_ids)
                .chain(&report.applied_motan_rule_ids)
        })
        .collect::<BTreeSet<_>>();
    reports
        .iter()
        .flat_map(|report| {
            report
                .unused_applicable_dynamic_rule_ids
                .iter()
                .chain(&report.unused_applicable_unordered_rule_ids)
                .chain(&report.unused_applicable_counter_rule_ids)
                .chain(&report.unused_applicable_motan_rule_ids)
        })
        .filter(|rule_id| !applied.contains(rule_id))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn discover_cases(root: &Path) -> Result<Vec<PathBuf>> {
    let mut cases = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("failed to scan {}", directory.display()))?
        {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| matches!(name, "failed" | "staging"))
            {
                continue;
            }
            let marker = path.join("case-kind.json");
            if marker.is_file() {
                let bytes = read_regular(&marker, "comparison recording case kind")?;
                let kind: CaseKind = serde_json::from_slice(&bytes)
                    .with_context(|| format!("invalid case kind {}", marker.display()))?;
                ensure!(
                    kind.version == 1 && kind.kind == "comparison_recording",
                    "unsupported comparison recording case kind in {}",
                    marker.display()
                );
                cases.push(path);
            } else {
                pending.push(path);
            }
        }
    }
    Ok(cases)
}

fn path_is_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect optional artifact {}", path.display())),
    }
}

fn write_report(path: &Path, report: &ComparisonVerificationReport) -> Result<()> {
    let mut payload =
        serde_json::to_vec_pretty(report).context("failed to serialize comparison report")?;
    payload.push(b'\n');
    if path.exists() {
        write_atomic(path, &payload)
    } else {
        create_atomic(path, &payload)
    }
    .with_context(|| format!("failed to write comparison report {}", path.display()))
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink"
    );
    std::fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
