use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

use super::model::{
    ActiveRunState, ApiExecution, AssertionCase, AssertionReport, CaseStatus,
    ResolvedProjectConfig, RunLayout,
};
use super::store;
use crate::case_group::CaseGroupInventory;
use crate::replay::{
    BackgroundReclassification, ReplayAggregateCounts, ReplayAggregateOptions,
    ReplayAggregateReport, aggregate_replay_report_with_options,
    reclassify_background_dependencies,
};

pub(super) fn build_final_evidence(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
) -> Result<()> {
    let reclassified = refresh_background_evidence(config, state)?;
    apply_reclassified_case_outcomes(state, &reclassified);
    build_final_evidence_from_current_report(config, layout, inventory, state)?;
    clear_resolved_dependency_errors(state);
    Ok(())
}

pub(super) fn refresh_background_evidence(
    config: &ResolvedProjectConfig,
    state: &ActiveRunState,
) -> Result<BackgroundReclassification> {
    let case_dirs = state
        .cases
        .iter()
        .map(|case| (case.case_id.clone(), case.case_dir.clone()))
        .collect::<BTreeMap<_, _>>();
    reclassify_background_dependencies(
        &config.source_traffic_policy,
        &state.replay_report,
        &case_dirs,
    )
}

pub(super) fn apply_reclassified_case_outcomes(
    state: &mut ActiveRunState,
    reclassified: &BackgroundReclassification,
) {
    for case in &mut state.cases {
        if matches!(case.status, CaseStatus::Pending | CaseStatus::Incomplete) {
            continue;
        }
        let dirty = reclassified
            .remaining_dirty_case_ids
            .contains(&case.case_id);
        case.replay_clean = Some(!dirty);
        case.status = if case.assertion_passed == Some(true) && !dirty {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        };
    }
}

pub(super) fn clear_resolved_dependency_errors(state: &mut ActiveRunState) {
    let clean_case_ids = state
        .cases
        .iter()
        .filter(|case| case.replay_clean == Some(true))
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let dependency_view_clean = dependency_view_is_clean(state);
    clear_resolved_dependency_error_messages(
        &mut state.errors,
        &clean_case_ids,
        dependency_view_clean,
    );
}

pub(super) fn clear_resolved_dependency_error_messages(
    errors: &mut Vec<String>,
    clean_case_ids: &BTreeSet<String>,
    dependency_view_clean: bool,
) {
    errors.retain(|error| {
        if is_clean_case_dependency_error(error, clean_case_ids) {
            return false;
        }
        !(dependency_view_clean && is_strict_dependency_finalize_error(error))
    });
}

pub(super) fn dependency_view_is_clean(state: &ActiveRunState) -> bool {
    state.replay_finalized
        && state.aggregate_complete
        && state.aggregate_clean
        && state
            .cases
            .iter()
            .all(|case| case.replay_clean == Some(true))
}

pub(super) fn is_clean_case_dependency_error(
    error: &str,
    clean_case_ids: &BTreeSet<String>,
) -> bool {
    let Some(rest) = error.strip_prefix("case ") else {
        return false;
    };
    let Some((case_id, _)) = rest.split_once(" replay evidence is dirty:") else {
        return false;
    };
    clean_case_ids.contains(case_id)
}

pub(super) fn is_strict_dependency_finalize_error(error: &str) -> bool {
    [
        "strict replay finalize failed: cannot finalize replay with dirty dependency evidence;",
        "strict replay finalize failed: cannot finalize replay with unmatched, unused, or unsupported exchanges;",
    ].iter().any(|prefix| error.starts_with(prefix))
}

pub(super) fn build_final_evidence_from_current_report(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
) -> Result<()> {
    let session_id = state
        .session_id
        .as_ref()
        .context("replay session id is missing")?;
    let all_case_ids = inventory
        .groups
        .iter()
        .flat_map(|group| group.cases.iter().map(|case| case.case_id.clone()))
        .collect::<BTreeSet<_>>();
    let aggregate = aggregate_replay_report_with_options(
        &layout.case_source,
        &state.replay_report,
        &ReplayAggregateOptions {
            case_ids: all_case_ids,
            session_ids: BTreeSet::from([session_id.clone()]),
        },
    )?;
    state.aggregate_complete = aggregate.is_complete();
    state.aggregate_clean = !aggregate.is_dirty();
    store::write_json(&state.aggregate_report, &aggregate)?;

    let assertion = assertion_report(
        state,
        config.runner_owned_response_assertions,
        state.cases.iter().map(|case| case.case_id.as_str()),
    );
    store::write_json(&state.assertions_report, &assertion)?;
    state.apis = build_api_evidence(config, layout, inventory, state, &aggregate)?;
    Ok(())
}

fn build_api_evidence(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &ActiveRunState,
    aggregate: &ReplayAggregateReport,
) -> Result<Vec<ApiExecution>> {
    let cases = state
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut apis = Vec::with_capacity(inventory.groups.len());
    for (position, group) in inventory.groups.iter().enumerate() {
        let report_dir = layout
            .active_dir
            .join("apis")
            .join(format!("api-{:04}", position + 1));
        std::fs::create_dir_all(&report_dir)?;
        let case_ids = group
            .cases
            .iter()
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>();
        let api_aggregate = aggregate_view(aggregate, &case_ids)?;
        let aggregate_path = report_dir.join("aggregate.json");
        store::write_json(&aggregate_path, &api_aggregate)?;
        let assertions = assertion_report(
            state,
            config.runner_owned_response_assertions,
            case_ids.iter().map(String::as_str),
        );
        let assertion_path = report_dir.join("assertions.json");
        store::write_json(&assertion_path, &assertions)?;

        let passed = case_ids
            .iter()
            .filter(|case_id| {
                cases
                    .get(case_id.as_str())
                    .is_some_and(|case| case.status == CaseStatus::Passed)
            })
            .count() as u32;
        let failed = case_ids
            .iter()
            .filter(|case_id| {
                cases.get(case_id.as_str()).is_some_and(|case| {
                    matches!(case.status, CaseStatus::Failed | CaseStatus::Incomplete)
                })
            })
            .count() as u32;
        let total = case_ids.len() as u32;
        let incomplete = total - passed - failed;
        let api_pattern = group
            .pattern
            .clone()
            .unwrap_or_else(|| group.source_route.clone());
        apis.push(ApiExecution {
            api_key: format!("{} {}", group.method, api_pattern),
            group_id: group.group_id.clone(),
            method: group.method.clone(),
            api_pattern,
            case_ids,
            total,
            passed,
            failed,
            incomplete,
            complete_pass: passed == total
                && api_aggregate.is_complete()
                && !api_aggregate.is_dirty(),
            report_dir,
        });
    }
    Ok(apis)
}

fn aggregate_view(
    aggregate: &ReplayAggregateReport,
    case_ids: &[String],
) -> Result<ReplayAggregateReport> {
    let selected = case_ids.iter().cloned().collect::<BTreeSet<_>>();
    let cases = aggregate
        .cases
        .iter()
        .filter(|case| selected.contains(&case.case_id))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        cases.len() == selected.len(),
        "global aggregate does not cover every API case"
    );
    let mut counts = ReplayAggregateCounts {
        reports: aggregate.counts.reports,
        published_cases: selected.len(),
        reported_cases: cases.len(),
        unreported_cases: 0,
        ..ReplayAggregateCounts::default()
    };
    for case in &cases {
        *counts.case_statuses.entry(case.status.clone()).or_insert(0) += 1;
    }
    Ok(ReplayAggregateReport {
        version: aggregate.version,
        case_source: aggregate.case_source.clone(),
        selected_case_ids: case_ids.to_vec(),
        selected_session_ids: aggregate.selected_session_ids.clone(),
        complete: aggregate.complete && cases.iter().all(|case| case.status == "ended"),
        dirty: aggregate.dirty,
        reports: aggregate.reports.clone(),
        cases,
        unreported_cases: Vec::new(),
        counts,
    })
}

fn assertion_report<'a>(
    state: &ActiveRunState,
    runner_owned: bool,
    case_ids: impl Iterator<Item = &'a str>,
) -> AssertionReport {
    let cases = state
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut report = AssertionReport::new(state, runner_owned);
    report.cases = case_ids
        .filter_map(|case_id| {
            let case = cases.get(case_id)?;
            let passed = case.assertion_passed?;
            Some(AssertionCase {
                case_id: case_id.to_string(),
                passed,
                response: case.response_assertion.clone(),
            })
        })
        .collect();
    report
}

pub(super) fn summarize_apis_without_aggregate(
    layout: &RunLayout,
    state: &mut ActiveRunState,
    inventory: &CaseGroupInventory,
) {
    let cases = state
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    state.apis = inventory
        .groups
        .iter()
        .enumerate()
        .map(|(position, group)| {
            let case_ids = group
                .cases
                .iter()
                .map(|case| case.case_id.clone())
                .collect::<Vec<_>>();
            let passed = case_ids
                .iter()
                .filter(|id| {
                    cases
                        .get(id.as_str())
                        .is_some_and(|case| case.status == CaseStatus::Passed)
                })
                .count() as u32;
            let failed = case_ids
                .iter()
                .filter(|id| {
                    cases.get(id.as_str()).is_some_and(|case| {
                        matches!(case.status, CaseStatus::Failed | CaseStatus::Incomplete)
                    })
                })
                .count() as u32;
            let total = case_ids.len() as u32;
            let api_pattern = group
                .pattern
                .clone()
                .unwrap_or_else(|| group.source_route.clone());
            ApiExecution {
                api_key: format!("{} {}", group.method, api_pattern),
                group_id: group.group_id.clone(),
                method: group.method.clone(),
                api_pattern,
                case_ids,
                total,
                passed,
                failed,
                incomplete: total - passed - failed,
                complete_pass: false,
                report_dir: layout
                    .active_dir
                    .join("apis")
                    .join(format!("api-{:04}", position + 1)),
            }
        })
        .collect();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup};

    #[test]
    fn assertion_report_omits_cases_without_an_assertion_result() {
        let inventory = CaseGroupInventory {
            case_source: PathBuf::from("/cases"),
            source_revision: "source".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api/devices".to_string(),
                method: "GET".to_string(),
                source_route: "/api/devices".to_string(),
                pattern: None,
                case_inventory_id: "inventory".to_string(),
                cases: ["passed", "failed", "pending"]
                    .into_iter()
                    .map(|case_id| CanonicalCase {
                        case_id: case_id.to_string(),
                        case_dir: PathBuf::from("/cases").join(case_id),
                        recorded_at: None,
                    })
                    .collect(),
            }],
        };
        let temp = tempfile::tempdir().unwrap();
        let mut state = ActiveRunState::new("run".to_string(), 1, &inventory, temp.path());
        let passed = state
            .cases
            .iter_mut()
            .find(|case| case.case_id == "passed")
            .unwrap();
        passed.assertion_passed = Some(true);
        passed.status = CaseStatus::Passed;
        let failed = state
            .cases
            .iter_mut()
            .find(|case| case.case_id == "failed")
            .unwrap();
        failed.assertion_passed = Some(false);
        failed.status = CaseStatus::Failed;

        let report = assertion_report(
            &state,
            true,
            state.cases.iter().map(|case| case.case_id.as_str()),
        );

        assert_eq!(report.cases.len(), 2);
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.case_id == "passed" && case.passed)
        );
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.case_id == "failed" && !case.passed)
        );
    }
}
