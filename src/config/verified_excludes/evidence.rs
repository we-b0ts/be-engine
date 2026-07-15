use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use hyper::Uri;
use serde::Deserialize;

use super::VerifiedApiExclude;
use crate::path_pattern::matches_segment_pattern;

const AGGREGATE_VERSION: u8 = 1;
const ASSERTION_REPORT_VERSION: u8 = 1;

pub(super) struct VerifiedEvidence {
    pub aggregate_path: PathBuf,
    pub aggregate_fingerprint: String,
    pub assertion_path: PathBuf,
    pub assertion_fingerprint: String,
    pub case_source: PathBuf,
    pub aggregate_complete: bool,
    pub aggregate_dirty: bool,
    pub matching_case_ids: Vec<String>,
    pub consecutive_success_case_ids: Vec<String>,
}

pub(super) fn load_verified_evidence(
    aggregate_report: &Path,
    assertion_report: &Path,
    candidate: &VerifiedApiExclude,
) -> Result<VerifiedEvidence> {
    let aggregate_path = canonical_file(aggregate_report, "aggregate report")?;
    let assertion_path = canonical_file(assertion_report, "assertion report")?;
    let aggregate_bytes = fs::read(&aggregate_path).with_context(|| {
        format!(
            "failed to read aggregate report {}",
            aggregate_path.display()
        )
    })?;
    let aggregate: AggregateEvidence = serde_json::from_slice(&aggregate_bytes)
        .with_context(|| format!("invalid aggregate report {}", aggregate_path.display()))?;
    ensure!(
        aggregate.version == AGGREGATE_VERSION,
        "unsupported aggregate report version {}; expected {AGGREGATE_VERSION}",
        aggregate.version
    );

    let assertion_bytes = fs::read(&assertion_path).with_context(|| {
        format!(
            "failed to read assertion report {}",
            assertion_path.display()
        )
    })?;
    let assertions: AssertionEvidence = serde_json::from_slice(&assertion_bytes)
        .with_context(|| format!("invalid assertion report {}", assertion_path.display()))?;
    ensure!(
        assertions.version == ASSERTION_REPORT_VERSION,
        "unsupported assertion report version {}; expected {ASSERTION_REPORT_VERSION}",
        assertions.version
    );
    ensure!(
        assertions.expected_response == "assertions_only",
        "assertion report expected_response must be assertions_only"
    );

    let case_source = canonical_dir(Path::new(&aggregate.case_source), "aggregate case source")?;
    let assertion_case_source =
        canonical_dir(Path::new(&assertions.case_source), "assertion case source")?;
    ensure!(
        case_source == assertion_case_source,
        "aggregate and assertion reports use different case sources"
    );

    let cases = matching_cases(&case_source, candidate)?;
    ensure!(
        !cases.is_empty(),
        "no published cases match the verified API exclude"
    );
    let matching_case_id_set = cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let selected_case_ids = aggregate
        .selected_case_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    ensure!(
        selected_case_ids == matching_case_id_set,
        "aggregate selected_case_ids must equal every published case matching {} {}",
        candidate.method,
        candidate.path_pattern
    );
    validate_aggregate_cases(&aggregate.cases, &matching_case_id_set)?;
    validate_aggregate_reports(&aggregate.reports)?;
    let assertion_results = assertion_results(assertions.cases, &matching_case_id_set)?;

    let mut consecutive_success_case_ids = cases
        .iter()
        .rev()
        .take_while(|case| assertion_results.get(&case.case_id) == Some(&true))
        .map(|case| case.case_id.clone())
        .collect::<Vec<_>>();
    consecutive_success_case_ids.reverse();

    Ok(VerifiedEvidence {
        aggregate_path,
        aggregate_fingerprint: fingerprint(&aggregate_bytes),
        assertion_path,
        assertion_fingerprint: fingerprint(&assertion_bytes),
        case_source,
        aggregate_complete: aggregate.complete,
        aggregate_dirty: aggregate.dirty,
        matching_case_ids: cases.into_iter().map(|case| case.case_id).collect(),
        consecutive_success_case_ids,
    })
}

#[derive(Debug, Deserialize)]
struct AggregateEvidence {
    version: u8,
    case_source: String,
    selected_case_ids: Vec<String>,
    complete: bool,
    dirty: bool,
    reports: Vec<AggregateReportEvidence>,
    cases: Vec<AggregateCaseEvidence>,
    #[serde(flatten)]
    _rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AggregateReportEvidence {
    path: String,
    complete: bool,
    dirty: bool,
    replay_policy: Option<AggregateReplayPolicyEvidence>,
    #[serde(flatten)]
    _rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateReplayPolicyEvidence {
    path: String,
    fingerprint: String,
    expected_response: String,
    unused_applicable_rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateCaseEvidence {
    case_id: String,
    status: String,
    report: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionEvidence {
    version: u8,
    case_source: String,
    expected_response: String,
    cases: Vec<AssertionCaseEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionCaseEvidence {
    case_id: String,
    passed: bool,
}

#[derive(Debug)]
struct RecordedCase {
    case_id: String,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RecordedRequest {
    timestamp: DateTime<Utc>,
    method: String,
    uri: String,
    matched_rule: Option<String>,
    #[serde(flatten)]
    _rest: BTreeMap<String, serde_json::Value>,
}

fn matching_cases(case_source: &Path, candidate: &VerifiedApiExclude) -> Result<Vec<RecordedCase>> {
    let mut cases = Vec::new();
    let mut case_ids = BTreeSet::new();
    let mut pending = vec![case_source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let request_path = directory.join("request.json");
        if request_path.is_file() {
            let expected = directory.join("expected-response.json");
            let alternate_expected = directory.join("expected_response.json");
            ensure!(
                expected.is_file() || alternate_expected.is_file(),
                "published case {} has no expected-response.json",
                directory.display()
            );
            let request: RecordedRequest = serde_json::from_slice(&fs::read(&request_path)?)
                .with_context(|| format!("invalid recorded request {}", request_path.display()))?;
            let path = request
                .uri
                .parse::<Uri>()
                .ok()
                .map(|uri| uri.path().to_string())
                .unwrap_or_else(|| {
                    request
                        .uri
                        .split('?')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                });
            if request.matched_rule.as_deref() == Some(candidate.rule.as_str())
                && request.method == candidate.method
                && matches_segment_pattern(&candidate.path_pattern, &path)
            {
                let case_id = directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("recorded case directory has no UTF-8 case id")?
                    .to_string();
                ensure!(
                    case_ids.insert(case_id.clone()),
                    "duplicate case id {case_id:?}"
                );
                cases.push(RecordedCase {
                    case_id,
                    timestamp: request.timestamp,
                });
            }
            continue;
        }
        for child in child_directories(&directory)? {
            if !should_skip(&child) {
                pending.push(child);
            }
        }
    }
    cases.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.case_id.cmp(&right.case_id))
    });
    Ok(cases)
}

fn validate_aggregate_cases(
    cases: &[AggregateCaseEvidence],
    matching_case_ids: &BTreeSet<String>,
) -> Result<()> {
    let mut reported = BTreeSet::new();
    for case in cases {
        ensure!(
            case.status == "ended",
            "aggregate case {:?} is not ended",
            case.case_id
        );
        ensure!(
            !case.report.trim().is_empty(),
            "aggregate case {:?} has no report path",
            case.case_id
        );
        ensure!(
            reported.insert(case.case_id.clone()),
            "aggregate repeats case {:?}",
            case.case_id
        );
    }
    ensure!(
        reported == *matching_case_ids,
        "aggregate reported cases must equal every published matching case"
    );
    Ok(())
}

fn validate_aggregate_reports(reports: &[AggregateReportEvidence]) -> Result<()> {
    ensure!(
        !reports.is_empty(),
        "aggregate report contains no replay reports"
    );
    for report in reports {
        ensure!(
            !report.path.trim().is_empty(),
            "aggregate replay report has no path"
        );
        ensure!(
            report.complete && !report.dirty,
            "aggregate replay report {} is incomplete or dirty",
            report.path
        );
        let policy = report.replay_policy.as_ref().with_context(|| {
            format!(
                "aggregate replay report {} has no replay policy evidence",
                report.path
            )
        })?;
        ensure!(
            !policy.path.trim().is_empty() && !policy.fingerprint.trim().is_empty(),
            "aggregate replay report {} has incomplete replay policy identity",
            report.path
        );
        ensure!(
            policy.expected_response == "assertions_only",
            "aggregate replay report {} does not declare assertions_only",
            report.path
        );
        ensure!(
            policy.unused_applicable_rule_ids.is_empty(),
            "aggregate replay report {} has unused applicable replay policy rules",
            report.path
        );
    }
    Ok(())
}

fn assertion_results(
    cases: Vec<AssertionCaseEvidence>,
    matching_case_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, bool>> {
    let mut results = BTreeMap::new();
    for case in cases {
        ensure!(
            results.insert(case.case_id.clone(), case.passed).is_none(),
            "assertion report repeats case {:?}",
            case.case_id
        );
    }
    ensure!(
        results.keys().cloned().collect::<BTreeSet<_>>() == *matching_case_ids,
        "assertion report cases must equal every published matching case"
    );
    Ok(results)
}

fn child_directories(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut children = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to scan case source {}", directory.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            children.push(entry.path());
        }
    }
    Ok(children)
}

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "failed" | "staging" | ".replay" | ".partial" | ".truncated"
            )
        })
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {label} {}", path.display()))?;
    ensure!(canonical.is_file(), "{label} must be a regular file");
    Ok(canonical)
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {label} {}", path.display()))?;
    ensure!(canonical.is_dir(), "{label} must be a directory");
    Ok(canonical)
}

fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}

pub(super) fn fingerprint_file(path: &Path, label: &str) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to reread {label} {}", path.display()))?;
    Ok(fingerprint(&bytes))
}
