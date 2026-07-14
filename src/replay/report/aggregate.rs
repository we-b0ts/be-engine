use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::Value;

const AGGREGATE_VERSION: u8 = 1;
const MIN_REPLAY_REPORT_VERSION: u64 = 2;
const MAX_REPLAY_REPORT_VERSION: u64 = 3;

#[derive(Debug, Clone, Serialize)]
pub struct ReplayAggregateReport {
    pub version: u8,
    pub case_source: String,
    pub complete: bool,
    pub dirty: bool,
    pub reports: Vec<ReplayReportSummary>,
    pub cases: Vec<ReplayAggregateCase>,
    pub unreported_cases: Vec<UnreportedCase>,
    pub counts: ReplayAggregateCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayReportSummary {
    pub path: String,
    pub version: u64,
    pub case_dir: String,
    pub complete: bool,
    pub dirty: bool,
    pub case_statuses: BTreeMap<String, usize>,
    pub counts: ReplayEventCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayAggregateCase {
    pub case_id: String,
    pub status: String,
    pub report: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnreportedCase {
    pub case_id: String,
    pub case_dir: String,
    pub dependencies_present: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReplayAggregateCounts {
    pub reports: usize,
    pub published_cases: usize,
    pub reported_cases: usize,
    pub unreported_cases: usize,
    pub case_statuses: BTreeMap<String, usize>,
    pub events: ReplayEventCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReplayEventCounts {
    pub mysql: MysqlEventCounts,
    pub http: HttpEventCounts,
    pub redis: CommandProtocolCounts,
    pub memcached: CommandProtocolCounts,
    pub kafka: CommandProtocolCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MysqlEventCounts {
    pub connections: usize,
    pub builtin_queries: usize,
    pub matched_queries: usize,
    pub unmatched_queries: usize,
    pub unsupported_commands: usize,
    pub unused_case_exchanges: usize,
    pub unused_bootstrap_exchanges: usize,
    pub metadata_warnings: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpEventCounts {
    pub matched_exchanges: usize,
    pub unmatched_requests: usize,
    pub unsupported_exchanges: usize,
    pub unused_case_exchanges: usize,
    pub unused_bootstrap_exchanges: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CommandProtocolCounts {
    pub connections: usize,
    pub matched: usize,
    pub unmatched: usize,
    pub unsupported: usize,
    pub unsafe_events: usize,
    pub unused_case: usize,
    pub unused_bootstrap: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub warnings: usize,
}

impl ReplayAggregateReport {
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

pub fn aggregate_replay_reports(case_source: &Path) -> Result<ReplayAggregateReport> {
    let case_source = canonical_dir(case_source, "case source")?;
    let published_cases = discover_published_cases(&case_source)?;
    let canonical_reports = discover_replay_reports(&case_source)?;

    let mut summaries = Vec::with_capacity(canonical_reports.len());
    let mut cases = Vec::new();
    let mut case_ids = BTreeSet::new();
    let mut aggregate_counts = ReplayAggregateCounts::default();

    for report_path in canonical_reports {
        ensure_within(&report_path, &case_source, "replay report")?;
        let payload = fs::read(&report_path)
            .with_context(|| format!("failed to read replay report {}", report_path.display()))?;
        let report: Value = serde_json::from_slice(&payload)
            .with_context(|| format!("invalid replay report JSON {}", report_path.display()))?;
        let summary = summarize_report(&case_source, &report_path, &report, &mut case_ids)?;
        for case in required_array(&report, "cases", &report_path)? {
            cases.push(ReplayAggregateCase {
                case_id: required_string(case, "case_id", &report_path)?.to_owned(),
                status: required_case_status(case, &report_path)?.to_owned(),
                report: report_path.display().to_string(),
            });
        }
        merge_statuses(&mut aggregate_counts.case_statuses, &summary.case_statuses);
        aggregate_counts.events.add(&summary.counts);
        summaries.push(summary);
    }

    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    for case_id in &case_ids {
        if !published_cases.contains_key(case_id) {
            bail!(
                "replay report references case id {case_id:?} that is not published under case source {}",
                case_source.display()
            );
        }
    }
    let unreported_cases = published_cases
        .iter()
        .filter(|(case_id, _)| !case_ids.contains(*case_id))
        .map(|(case_id, case)| UnreportedCase {
            case_id: case_id.clone(),
            case_dir: case.case_dir.display().to_string(),
            dependencies_present: case.dependencies_present,
        })
        .collect::<Vec<_>>();
    aggregate_counts.reports = summaries.len();
    aggregate_counts.published_cases = published_cases.len();
    aggregate_counts.reported_cases = cases.len();
    aggregate_counts.unreported_cases = unreported_cases.len();
    let complete = unreported_cases.is_empty()
        && !cases.is_empty()
        && cases.iter().all(|case| case.status == "ended");
    let dirty = summaries.iter().any(|report| report.dirty);

    Ok(ReplayAggregateReport {
        version: AGGREGATE_VERSION,
        case_source: case_source.display().to_string(),
        complete,
        dirty,
        reports: summaries,
        cases,
        unreported_cases,
        counts: aggregate_counts,
    })
}

#[derive(Debug)]
struct PublishedCase {
    case_dir: PathBuf,
    dependencies_present: bool,
}

fn discover_published_cases(case_source: &Path) -> Result<BTreeMap<String, PublishedCase>> {
    let mut cases = BTreeMap::new();
    let mut pending = vec![case_source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let request = directory.join("request.json");
        let expected = directory.join("expected-response.json");
        let alternate_expected = directory.join("expected_response.json");
        let has_request = request.is_file();
        let has_expected = expected.is_file() || alternate_expected.is_file();
        if has_request || has_expected {
            if !has_request || !has_expected {
                bail!(
                    "incomplete published replay case {}; request.json and expected-response.json are both required",
                    directory.display()
                );
            }
            let case_id = directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    anyhow!(
                        "replay case path has no UTF-8 case id: {}",
                        directory.display()
                    )
                })?
                .to_owned();
            if cases
                .insert(
                    case_id.clone(),
                    PublishedCase {
                        case_dir: directory.clone(),
                        dependencies_present: directory.join("dependencies.jsonl").is_file(),
                    },
                )
                .is_some()
            {
                bail!("duplicate published replay case id {case_id:?}");
            }
            continue;
        }
        for child in child_directories(&directory)? {
            if child.file_name().is_none_or(|name| name != ".replay")
                && !should_skip_scan_dir(&child)
            {
                pending.push(child);
            }
        }
    }
    if cases.is_empty() {
        bail!(
            "no published replay cases found under case source {}",
            case_source.display()
        );
    }
    Ok(cases)
}

fn discover_replay_reports(case_source: &Path) -> Result<Vec<PathBuf>> {
    let mut reports = Vec::new();
    let mut pending = vec![case_source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for child in child_directories(&directory)? {
            if should_skip_scan_dir(&child) {
                continue;
            }
            if child.file_name().is_some_and(|name| name == ".replay") {
                let report = child.join("replay-report.json");
                if report.is_file() {
                    reports.push(canonical_file(&report, "replay report")?);
                }
                continue;
            }
            pending.push(child);
        }
    }
    reports.sort();
    reports.dedup();
    Ok(reports)
}

fn child_directories(directory: &Path) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to scan case source {}", directory.display()))?;
    let mut children = Vec::new();
    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", directory.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
        if file_type.is_dir() {
            children.push(entry.path());
        }
    }
    Ok(children)
}

fn should_skip_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "failed" | "staging" | ".partial" | ".truncated"))
}

fn summarize_report(
    case_source: &Path,
    report_path: &Path,
    report: &Value,
    case_ids: &mut BTreeSet<String>,
) -> Result<ReplayReportSummary> {
    let report_object = report.as_object().ok_or_else(|| {
        anyhow!(
            "replay report {} must be a JSON object",
            report_path.display()
        )
    })?;
    let version = report_object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            anyhow!(
                "replay report {} has no numeric version",
                report_path.display()
            )
        })?;
    if !(MIN_REPLAY_REPORT_VERSION..=MAX_REPLAY_REPORT_VERSION).contains(&version) {
        bail!(
            "unsupported replay report version {version} in {}; supported versions are {MIN_REPLAY_REPORT_VERSION}..={MAX_REPLAY_REPORT_VERSION}",
            report_path.display()
        );
    }
    let case_dir_value = report_object
        .get("case_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("replay report {} has no case_dir", report_path.display()))?;
    let case_dir = canonical_dir(Path::new(case_dir_value), "replay report case_dir")?;
    ensure_within(&case_dir, case_source, "replay report case_dir")?;

    let mut case_statuses = BTreeMap::new();
    let report_name = report_path.display().to_string();
    for case in required_array(report, "cases", report_path)? {
        let case_id = required_string(case, "case_id", report_path)?;
        if !case_ids.insert(case_id.to_owned()) {
            bail!("duplicate replay case id {case_id:?} across aggregate reports");
        }
        let status = required_case_status(case, report_path)?;
        *case_statuses.entry(status.to_owned()).or_insert(0) += 1;
    }
    let complete = case_statuses
        .iter()
        .all(|(status, count)| status == "ended" || *count == 0);
    let counts = event_counts(report, version, report_path)?;
    let dirty = counts.is_dirty();

    Ok(ReplayReportSummary {
        path: report_name,
        version,
        case_dir: case_dir.display().to_string(),
        complete,
        dirty,
        case_statuses,
        counts,
    })
}

fn event_counts(report: &Value, version: u64, path: &Path) -> Result<ReplayEventCounts> {
    Ok(ReplayEventCounts {
        mysql: MysqlEventCounts {
            connections: required_usize(report, "connections", path)?,
            builtin_queries: required_len(report, "builtin_queries", path)?,
            matched_queries: required_len(report, "matched_queries", path)?,
            unmatched_queries: required_len(report, "unmatched_queries", path)?,
            unsupported_commands: required_len(report, "unsupported_commands", path)?,
            unused_case_exchanges: required_len(report, "unused_case_exchanges", path)?,
            unused_bootstrap_exchanges: required_len(report, "unused_bootstrap_exchanges", path)?,
            metadata_warnings: required_len(report, "metadata_warnings", path)?,
        },
        http: HttpEventCounts {
            matched_exchanges: required_len(report, "matched_http_exchanges", path)?,
            unmatched_requests: required_len(report, "unmatched_http_requests", path)?,
            unsupported_exchanges: required_len(report, "unsupported_http_exchanges", path)?,
            unused_case_exchanges: required_len(report, "unused_case_http_exchanges", path)?,
            unused_bootstrap_exchanges: required_len(
                report,
                "unused_bootstrap_http_exchanges",
                path,
            )?,
        },
        redis: protocol_counts(report, "redis", version >= 3, path)?,
        memcached: protocol_counts(report, "memcached", version >= 3, path)?,
        kafka: protocol_counts(report, "kafka", version >= 3, path)?,
    })
}

fn protocol_counts(
    report: &Value,
    protocol: &str,
    required: bool,
    path: &Path,
) -> Result<CommandProtocolCounts> {
    let Some(value) = report.get(protocol) else {
        if required {
            bail!(
                "replay report {} version 3 is missing {protocol}",
                path.display()
            );
        }
        return Ok(CommandProtocolCounts::default());
    };
    if !value.is_object() {
        bail!(
            "replay report {} field {protocol} must be an object",
            path.display()
        );
    }
    Ok(CommandProtocolCounts {
        connections: required_usize(value, "connections", path)?,
        matched: required_len(value, "matched", path)?,
        unmatched: required_len(value, "unmatched", path)?,
        unsupported: required_len(value, "unsupported", path)?,
        unsafe_events: required_len(value, "unsafe_events", path)?,
        unused_case: required_len(value, "unused_case", path)?,
        unused_bootstrap: required_len(value, "unused_bootstrap", path)?,
        warnings: optional_len(value, "warnings", path)?,
    })
}

fn required_case_status<'a>(case: &'a Value, path: &Path) -> Result<&'a str> {
    let status = required_string(case, "status", path)?;
    if !matches!(status, "pending" | "active" | "ended") {
        bail!(
            "replay report {} contains unknown case status {status:?}",
            path.display()
        );
    }
    Ok(status)
}

fn required_string<'a>(value: &'a Value, field: &str, path: &Path) -> Result<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        anyhow!(
            "replay report {} field {field} must be a string",
            path.display()
        )
    })
}

fn required_array<'a>(value: &'a Value, field: &str, path: &Path) -> Result<&'a Vec<Value>> {
    value.get(field).and_then(Value::as_array).ok_or_else(|| {
        anyhow!(
            "replay report {} field {field} must be an array",
            path.display()
        )
    })
}

fn required_len(value: &Value, field: &str, path: &Path) -> Result<usize> {
    Ok(required_array(value, field, path)?.len())
}

fn optional_len(value: &Value, field: &str, path: &Path) -> Result<usize> {
    match value.get(field) {
        Some(_) => required_len(value, field, path),
        None => Ok(0),
    }
}

fn required_usize(value: &Value, field: &str, path: &Path) -> Result<usize> {
    let number = value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        anyhow!(
            "replay report {} field {field} must be a non-negative integer",
            path.display()
        )
    })?;
    usize::try_from(number).with_context(|| {
        format!(
            "replay report {} field {field} does not fit usize",
            path.display()
        )
    })
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {label} {}", path.display()))?;
    if !canonical.is_dir() {
        bail!("{label} {} is not a directory", canonical.display());
    }
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {label} {}", path.display()))?;
    if !canonical.is_file() {
        bail!("{label} {} is not a file", canonical.display());
    }
    Ok(canonical)
}

fn ensure_within(path: &Path, root: &Path, label: &str) -> Result<()> {
    if !path.starts_with(root) {
        bail!(
            "{label} {} is outside case source {}",
            path.display(),
            root.display()
        );
    }
    Ok(())
}

fn merge_statuses(target: &mut BTreeMap<String, usize>, source: &BTreeMap<String, usize>) {
    for (status, count) in source {
        *target.entry(status.clone()).or_insert(0) += count;
    }
}

impl ReplayEventCounts {
    fn add(&mut self, other: &Self) {
        self.mysql.add(&other.mysql);
        self.http.add(&other.http);
        self.redis.add(&other.redis);
        self.memcached.add(&other.memcached);
        self.kafka.add(&other.kafka);
    }

    fn is_dirty(&self) -> bool {
        self.mysql.is_dirty()
            || self.http.is_dirty()
            || self.redis.is_dirty()
            || self.memcached.is_dirty()
            || self.kafka.is_dirty()
    }
}

impl MysqlEventCounts {
    fn add(&mut self, other: &Self) {
        self.connections += other.connections;
        self.builtin_queries += other.builtin_queries;
        self.matched_queries += other.matched_queries;
        self.unmatched_queries += other.unmatched_queries;
        self.unsupported_commands += other.unsupported_commands;
        self.unused_case_exchanges += other.unused_case_exchanges;
        self.unused_bootstrap_exchanges += other.unused_bootstrap_exchanges;
        self.metadata_warnings += other.metadata_warnings;
    }

    fn is_dirty(&self) -> bool {
        self.unmatched_queries > 0
            || self.unsupported_commands > 0
            || self.unused_case_exchanges > 0
            || self.unused_bootstrap_exchanges > 0
    }
}

impl HttpEventCounts {
    fn add(&mut self, other: &Self) {
        self.matched_exchanges += other.matched_exchanges;
        self.unmatched_requests += other.unmatched_requests;
        self.unsupported_exchanges += other.unsupported_exchanges;
        self.unused_case_exchanges += other.unused_case_exchanges;
        self.unused_bootstrap_exchanges += other.unused_bootstrap_exchanges;
    }

    fn is_dirty(&self) -> bool {
        self.unmatched_requests > 0
            || self.unsupported_exchanges > 0
            || self.unused_case_exchanges > 0
            || self.unused_bootstrap_exchanges > 0
    }
}

impl CommandProtocolCounts {
    fn add(&mut self, other: &Self) {
        self.connections += other.connections;
        self.matched += other.matched;
        self.unmatched += other.unmatched;
        self.unsupported += other.unsupported;
        self.unsafe_events += other.unsafe_events;
        self.unused_case += other.unused_case;
        self.unused_bootstrap += other.unused_bootstrap;
        self.warnings += other.warnings;
    }

    fn is_dirty(&self) -> bool {
        self.unmatched > 0
            || self.unsupported > 0
            || self.unsafe_events > 0
            || self.unused_case > 0
            || self.unused_bootstrap > 0
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}
