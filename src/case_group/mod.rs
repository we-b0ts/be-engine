mod discovery;
mod index;
mod snapshot;

pub(crate) use snapshot::{PreparedGroupMembership, load_prepared_membership};

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{CasePathPatternAuthority, CasePathPatternFeedback, plan_case_path_pattern_feedback};

use self::discovery::{
    discover_published_cases, portable_inventory_id, reject_duplicate_case_ids, resolve_member_dir,
    select_group_cases,
};
use self::index::{
    CaseGroupRecord, IndexPathStorage, case_inventory_id, legacy_index_locations,
    load_or_create_index, prepare_output_path, reject_membership_overlap, reject_route_overlap,
    validate_index, validate_loaded_index, write_index,
};

#[derive(Debug, Clone)]
pub struct CaseGroupOptions {
    pub case_source: PathBuf,
    pub case_dir: PathBuf,
    pub method: String,
    pub source_route: String,
    pub pattern: Option<String>,
    pub source_revision: String,
    pub output: PathBuf,
    pub recorder_config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseGroupStatus {
    Created,
    AlreadyGrouped,
    AlreadyCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternOutcomeStatus {
    NotRequiredStatic,
    Applied,
    ConfirmedExisting,
    NotApplicableMissingManagedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternOutcome {
    pub status: PatternOutcomeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
    pub added: Vec<String>,
    pub patterns_after: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseGroupEnsureResult {
    pub status: CaseGroupStatus,
    pub group_id: String,
    pub method: String,
    pub source_route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    pub pattern_outcome: PatternOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_dir: Option<PathBuf>,
    pub manifest: PathBuf,
    pub case_ids: Vec<String>,
    pub member_dirs: Vec<PathBuf>,
    pub source_revision: String,
    pub case_inventory_id: String,
    pub report_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalCase {
    pub case_id: String,
    pub case_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalCaseGroup {
    pub group_id: String,
    pub method: String,
    pub source_route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    pub case_inventory_id: String,
    pub cases: Vec<CanonicalCase>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseGroupInventory {
    pub case_source: PathBuf,
    pub source_revision: String,
    pub case_inventory_id: String,
    pub groups: Vec<CanonicalCaseGroup>,
}

pub fn resolve_recording_api_member(
    case_source: &Path,
    api: &crate::RecordingApi,
) -> Result<PathBuf> {
    let members = resolve_recording_api_members(case_source, api)?;
    ensure!(
        members.len() == 1,
        "recording API {api} must resolve to exactly one canonical member directory, found {}",
        members.len()
    );
    Ok(members.into_iter().next().expect("one member was required"))
}

pub fn resolve_recording_api_case_ids(
    case_source: &Path,
    apis: &[crate::RecordingApi],
) -> Result<Vec<String>> {
    ensure!(!apis.is_empty(), "at least one replay API is required");
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;

    let mut selectors = BTreeSet::new();
    for api in apis {
        ensure!(
            selectors.insert(api.to_string()),
            "duplicate replay API selector: {api}"
        );
    }

    let mut matched = vec![0_usize; apis.len()];
    let mut selected = Vec::new();
    for case in cases {
        let method = case.method.parse().with_context(|| {
            format!(
                "recorded case {} has invalid method {:?}",
                case.dir.display(),
                case.method
            )
        })?;
        let uri = case.path.parse().with_context(|| {
            format!(
                "recorded case {} has invalid path {:?}",
                case.dir.display(),
                case.path
            )
        })?;
        let owners = apis
            .iter()
            .enumerate()
            .filter(|(_, api)| api.matches(&method, &uri))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        ensure!(
            owners.len() <= 1,
            "recorded case {} matches overlapping replay API selectors: {}",
            case.id,
            owners
                .iter()
                .map(|index| apis[*index].to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(index) = owners.first().copied() {
            matched[index] = matched[index].saturating_add(1);
            selected.push(case.id);
        }
    }
    for (index, api) in apis.iter().enumerate() {
        ensure!(
            matched[index] > 0,
            "recording API {api} has no recorded cases"
        );
    }
    Ok(selected)
}

pub(crate) fn resolve_recording_api_seed_member(
    case_source: &Path,
    api: &crate::RecordingApi,
) -> Result<PathBuf> {
    let members = resolve_recording_api_members(case_source, api)?;
    members
        .into_iter()
        .next()
        .context("recording API has no canonical member directory")
}

/// Validate a recording inventory with one case-source discovery. A selected
/// recording can contain many APIs, so rediscovering every case for each API
/// makes read-only coordinator status proportional to APIs times cases.
pub(crate) fn validate_recording_api_cases(
    case_source: &Path,
    apis: &[crate::RecordingApi],
) -> Result<()> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    for api in apis {
        ensure!(
            cases.iter().any(|case| {
                let Ok(method) = case.method.parse() else {
                    return false;
                };
                let Ok(uri) = case.path.parse() else {
                    return false;
                };
                api.matches(&method, &uri)
            }),
            "recording API {api} has no recorded cases"
        );
    }
    Ok(())
}

fn resolve_recording_api_members(
    case_source: &Path,
    api: &crate::RecordingApi,
) -> Result<BTreeSet<PathBuf>> {
    Ok(resolve_recording_api_cases(case_source, api)?
        .into_iter()
        .map(|case| case.member_dir)
        .collect())
}

fn resolve_recording_api_cases(
    case_source: &Path,
    api: &crate::RecordingApi,
) -> Result<Vec<discovery::PublishedCase>> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    let selected = cases
        .into_iter()
        .filter(|case| {
            let Ok(method) = case.method.parse() else {
                return false;
            };
            let Ok(uri) = case.path.parse() else {
                return false;
            };
            api.matches(&method, &uri)
        })
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "recording API {api} has no recorded cases"
    );
    Ok(selected)
}

pub(crate) fn resolve_published_case_dir(case_source: &Path, case_id: &str) -> Result<PathBuf> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    cases
        .into_iter()
        .find(|case| case.id == case_id)
        .map(|case| case.dir)
        .with_context(|| {
            format!(
                "recorded case {case_id:?} is not part of case source {}",
                case_source.display()
            )
        })
}

pub(crate) fn published_request_paths(case_source: &Path) -> Result<Vec<PathBuf>> {
    let cases = discover_published_cases(case_source)?;
    reject_duplicate_case_ids(&cases)?;
    Ok(cases
        .into_iter()
        .map(|case| case.dir.join("request.json"))
        .collect())
}

pub(crate) fn published_case_dependency_paths(case_source: &Path) -> Result<Vec<PathBuf>> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    cases
        .into_iter()
        .map(|case| {
            let path = case.dir.join("dependencies.jsonl");
            ensure!(
                path.is_file(),
                "published case {} has no dependencies.jsonl",
                case.dir.display()
            );
            Ok(path)
        })
        .collect()
}

pub fn ensure_case_group(options: CaseGroupOptions) -> Result<CaseGroupEnsureResult> {
    ensure_case_group_impl(options, None)
}

pub(crate) fn ensure_case_group_with_target_root(
    options: CaseGroupOptions,
    target_root: &Path,
) -> Result<CaseGroupEnsureResult> {
    ensure_case_group_impl(options, Some(target_root))
}

fn ensure_case_group_impl(
    options: CaseGroupOptions,
    target_root: Option<&Path>,
) -> Result<CaseGroupEnsureResult> {
    validate_options(&options)?;
    let case_source = fs::canonicalize(&options.case_source).with_context(|| {
        format!(
            "failed to resolve case source {}",
            options.case_source.display()
        )
    })?;
    let requested_dir = fs::canonicalize(&options.case_dir).with_context(|| {
        format!(
            "failed to resolve case directory {}",
            options.case_dir.display()
        )
    })?;
    ensure!(
        requested_dir.starts_with(&case_source),
        "case directory {} is outside case source {}",
        requested_dir.display(),
        case_source.display()
    );
    let output = prepare_output_path(&options.output, &case_source)?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    let current_dir = resolve_member_dir(&requested_dir, &cases)?;

    let method = options.method.trim().to_ascii_uppercase();
    let pattern = options
        .pattern
        .as_deref()
        .map(validate_pattern)
        .transpose()?;
    let source_route = if pattern.is_some() {
        normalize_route(&options.source_route, "source route")?
    } else {
        crate::path_pattern::validate_literal_path(&options.source_route)
            .context("invalid exact source route")?;
        options.source_route.clone()
    };
    if let Some(pattern) = &pattern {
        validate_pattern_against_source_route(pattern, &source_route)?;
    }
    let group_id = format!("{} {}", method, pattern.as_deref().unwrap_or(&source_route));

    let mut index =
        load_or_create_index(&output, &case_source, &options.source_revision, target_root)?;
    let storage = IndexPathStorage::for_index(&index, &case_source)?;
    validate_index(&index, &storage, &case_source, &cases)?;

    if let Some(existing) = index.groups.iter().find(|group| group.group_id == group_id) {
        ensure!(
            existing.method == method
                && existing.source_route == source_route
                && existing.pattern == pattern
                && existing.member_dirs.iter().any(|member| {
                    storage
                        .resolve(member)
                        .is_ok_and(|path| path == current_dir)
                }),
            "group {group_id} already exists with a different route or membership; the index is stale"
        );
        let status = if existing.group_dir.is_some() {
            CaseGroupStatus::AlreadyCanonical
        } else {
            CaseGroupStatus::AlreadyGrouped
        };
        return result_from_record(existing, status, &index.source_revision, &storage, &output);
    }

    reject_route_overlap(&index.groups, &method, &source_route, pattern.as_deref())?;

    let selected = select_group_cases(
        &cases,
        &current_dir,
        &method,
        &source_route,
        pattern.as_deref(),
    )?;
    let case_ids = selected
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    let member_dirs = selected
        .iter()
        .map(|case| case.member_dir.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    reject_membership_overlap(&index.groups, &case_ids)?;
    let case_inventory_id = case_inventory_id(&index, &case_source, &selected)?;
    let pattern_outcome = apply_pattern_feedback(
        pattern.as_deref(),
        &case_source,
        &options.source_revision,
        options.recorder_config.as_deref(),
    )?;
    let whole_directory = pattern.is_none()
        && member_dirs.len() == 1
        && cases
            .iter()
            .filter(|case| case.member_dir == current_dir)
            .count()
            == selected.len();
    let group_dir = whole_directory
        .then(|| storage.persist(&current_dir))
        .transpose()?;
    let status = if whole_directory {
        CaseGroupStatus::AlreadyCanonical
    } else {
        CaseGroupStatus::Created
    };
    let record = CaseGroupRecord {
        status,
        group_id: group_id.clone(),
        method,
        source_route,
        pattern,
        pattern_outcome,
        group_dir,
        case_ids,
        member_dirs: member_dirs
            .iter()
            .map(|member| storage.persist(member))
            .collect::<Result<Vec<_>>>()?,
        case_inventory_id,
        manifest: storage.persist(&output)?,
        report_path: storage.persist(&output)?,
    };
    index.groups.push(record);
    index
        .groups
        .sort_by(|left, right| left.group_id.cmp(&right.group_id));
    write_index(&output, &index)?;
    let persisted = index
        .groups
        .iter()
        .find(|group| group.group_id == group_id)
        .context("persisted case group disappeared from index")?;
    result_from_record(persisted, status, &index.source_revision, &storage, &output)
}

pub fn load_complete_case_group_inventory(
    output: &Path,
    case_source: &Path,
) -> Result<CaseGroupInventory> {
    load_case_group_inventory_impl(output, case_source, true)
}

pub fn load_case_group_inventory(output: &Path, case_source: &Path) -> Result<CaseGroupInventory> {
    load_case_group_inventory_impl(output, case_source, false)
}

pub(crate) fn load_legacy_complete_case_group_inventory(
    copied_output: &Path,
) -> Result<CaseGroupInventory> {
    let copied_output = fs::canonicalize(copied_output).with_context(|| {
        format!(
            "failed to resolve copied group index {}",
            copied_output.display()
        )
    })?;
    let copied_index = index::read_index(&copied_output)?;
    let (case_source, original_output) = legacy_index_locations(&copied_index)?;
    validate_single_line("source revision", &copied_index.source_revision)?;
    let original_output = fs::canonicalize(&original_output).with_context(|| {
        format!(
            "failed to resolve original legacy group index {}",
            original_output.display()
        )
    })?;
    ensure!(
        fs::read(&copied_output)? == fs::read(&original_output)?,
        "copied legacy group index differs from its original index"
    );
    load_case_group_inventory_impl(&original_output, &case_source, true)
}

pub(crate) fn portable_case_inventory_id(case_source: &Path) -> Result<String> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    portable_inventory_id(&case_source, &cases)
}

pub(crate) fn legacy_case_inventory_id(case_source: &Path) -> Result<String> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;
    Ok(discovery::inventory_id(&cases))
}

fn load_case_group_inventory_impl(
    output: &Path,
    case_source: &Path,
    require_complete: bool,
) -> Result<CaseGroupInventory> {
    let case_source = fs::canonicalize(case_source)
        .with_context(|| format!("failed to resolve case source {}", case_source.display()))?;
    let cases = discover_published_cases(&case_source)?;
    ensure!(!cases.is_empty(), "case source contains no published cases");
    reject_duplicate_case_ids(&cases)?;

    let output = fs::canonicalize(output)
        .with_context(|| format!("failed to resolve group index {}", output.display()))?;
    let index = index::read_index(&output)?;
    let storage = IndexPathStorage::for_index(&index, &case_source)?;
    validate_loaded_index(&index, &storage, &output, &case_source, &cases)?;

    let cases_by_id = cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut selected_ids = BTreeSet::new();
    let mut groups = Vec::with_capacity(index.groups.len());
    for group in &index.groups {
        let mut selected_cases = Vec::with_capacity(group.case_ids.len());
        for case_id in &group.case_ids {
            let case = cases_by_id.get(case_id.as_str()).with_context(|| {
                format!("group {} references missing case {case_id}", group.group_id)
            })?;
            ensure!(
                selected_ids.insert(case_id.clone()),
                "case id {case_id} belongs to overlapping groups"
            );
            selected_cases.push(CanonicalCase {
                case_id: case_id.clone(),
                case_dir: case.dir.clone(),
                recorded_at: case.recorded_at,
            });
        }
        groups.push(CanonicalCaseGroup {
            group_id: group.group_id.clone(),
            method: group.method.clone(),
            source_route: group.source_route.clone(),
            pattern: group.pattern.clone(),
            case_inventory_id: group.case_inventory_id.clone(),
            cases: selected_cases,
        });
    }

    let published_ids = cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<BTreeSet<_>>();
    let ungrouped = published_ids
        .difference(&selected_ids)
        .cloned()
        .collect::<Vec<_>>();
    if require_complete {
        ensure!(
            ungrouped.is_empty(),
            "case group index does not cover published cases: {}",
            ungrouped.join(", ")
        );
    }

    let case_inventory_id = case_inventory_id(&index, &case_source, &cases)?;
    Ok(CaseGroupInventory {
        case_source,
        source_revision: index.source_revision,
        case_inventory_id,
        groups,
    })
}

fn validate_options(options: &CaseGroupOptions) -> Result<()> {
    validate_single_line("method", &options.method)?;
    validate_single_line("source revision", &options.source_revision)?;
    Ok(())
}

fn validate_single_line(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    ensure!(
        !value.contains(['\r', '\n']),
        "{label} must fit on one line"
    );
    Ok(())
}

fn normalize_route(route: &str, label: &str) -> Result<String> {
    validate_single_line(label, route)?;
    ensure!(route.starts_with('/'), "{label} must start with '/'");
    ensure!(
        !route.contains(['?', '#']),
        "{label} must not include a query or fragment"
    );
    ensure!(
        route == "/" || !route.ends_with('/'),
        "{label} must not have a trailing slash"
    );
    ensure!(
        !route.contains("//"),
        "{label} must not contain empty segments"
    );
    Ok(route.to_string())
}

fn validate_pattern(pattern: &str) -> Result<String> {
    let pattern = normalize_route(pattern, "case path pattern")?;
    ensure!(
        pattern
            .split('/')
            .any(|segment| segment == "*" || segment == "**"),
        "dynamic case path pattern must contain at least one whole-segment '*' or trailing '**'"
    );
    ensure!(
        pattern
            .split('/')
            .all(|segment| !segment.contains('*') || segment == "*" || segment == "**"),
        "case path pattern wildcards must occupy a complete path segment"
    );
    let segments = pattern.split('/').collect::<Vec<_>>();
    ensure!(
        segments
            .iter()
            .enumerate()
            .all(|(index, segment)| *segment != "**" || index == segments.len() - 1),
        "case path pattern '**' catch-all must be the final path segment"
    );
    Ok(pattern)
}

pub(crate) fn validate_pattern_against_source_route(
    pattern: &str,
    source_route: &str,
) -> Result<()> {
    let pattern = validate_pattern(pattern)?;
    let source_route = normalize_route(source_route, "source route")?;
    let pattern_segments = pattern.split('/').collect::<Vec<_>>();
    let route_segments = source_route.split('/').collect::<Vec<_>>();
    ensure!(
        pattern_segments.len() == route_segments.len(),
        "case path pattern and source route must have the same segment count: pattern {pattern:?}, source route {source_route:?}; include all router mount prefixes"
    );
    let route_segment_count = route_segments.len();
    for (index, (pattern_segment, route_segment)) in
        pattern_segments.into_iter().zip(route_segments).enumerate()
    {
        let matches = if pattern_segment == "*" {
            dynamic_source_segment(route_segment)
        } else if pattern_segment == "**" {
            index + 1 == route_segment_count && dynamic_source_segment(route_segment)
        } else {
            pattern_segment == route_segment && !dynamic_source_segment(route_segment)
        };
        ensure!(
            matches,
            "case path pattern {pattern} does not match dynamic source route {source_route}"
        );
    }
    Ok(())
}

fn dynamic_source_segment(segment: &str) -> bool {
    segment == "*"
        || (segment.len() > 1 && (segment.starts_with(':') || segment.starts_with('*')))
        || (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
}

fn apply_pattern_feedback(
    pattern: Option<&str>,
    case_source: &Path,
    source_revision: &str,
    recorder_config: Option<&Path>,
) -> Result<PatternOutcome> {
    let Some(pattern) = pattern else {
        return Ok(PatternOutcome {
            status: PatternOutcomeStatus::NotRequiredStatic,
            config: None,
            added: Vec::new(),
            patterns_after: Vec::new(),
        });
    };
    let Some(config) = recorder_config else {
        return Ok(PatternOutcome {
            status: PatternOutcomeStatus::NotApplicableMissingManagedConfig,
            config: None,
            added: Vec::new(),
            patterns_after: Vec::new(),
        });
    };
    let rules_path = crate::config::resolve_unified_policy_path(config)?;
    let plan = plan_case_path_pattern_feedback(CasePathPatternFeedback {
        project_config_path: config.to_path_buf(),
        rules_path,
        source_revision: source_revision.to_string(),
        case_source: case_source.display().to_string(),
        authority: CasePathPatternAuthority::Focused,
        patterns: vec![pattern.to_string()],
        incorrect_patterns: Vec::new(),
        correction_evidence: None,
    })?;
    let changed = plan.report().changed;
    let report = plan.apply(false)?;
    Ok(PatternOutcome {
        status: if changed {
            PatternOutcomeStatus::Applied
        } else {
            PatternOutcomeStatus::ConfirmedExisting
        },
        config: Some(report.rules),
        added: report.added,
        patterns_after: report.patterns_after,
    })
}

fn result_from_record(
    record: &CaseGroupRecord,
    status: CaseGroupStatus,
    source_revision: &str,
    storage: &IndexPathStorage,
    output: &Path,
) -> Result<CaseGroupEnsureResult> {
    Ok(CaseGroupEnsureResult {
        status,
        group_id: record.group_id.clone(),
        method: record.method.clone(),
        source_route: record.source_route.clone(),
        pattern: record.pattern.clone(),
        pattern_outcome: record.pattern_outcome.clone(),
        group_dir: record
            .group_dir
            .as_deref()
            .map(|path| storage.resolve(path))
            .transpose()?,
        manifest: output.to_path_buf(),
        case_ids: record.case_ids.clone(),
        member_dirs: record
            .member_dirs
            .iter()
            .map(|path| storage.resolve(path))
            .collect::<Result<Vec<_>>>()?,
        source_revision: source_revision.to_string(),
        case_inventory_id: record.case_inventory_id.clone(),
        report_path: output.to_path_buf(),
    })
}

#[cfg(test)]
mod tests;
