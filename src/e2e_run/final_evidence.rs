//! Derive summaries from actual Replay facts without changing case outcomes.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

use super::model::{
    ActiveRunState, ApiExecution, AssertionCase, AssertionReport, CaseStatus,
    ResolvedProjectConfig, RunLayout,
};
use super::store;
use crate::case_group::CaseGroupInventory;
use crate::replay::{
    ReplayAggregateCounts, ReplayAggregateOptions, ReplayAggregateReport,
    aggregate_runner_replay_report,
};

pub(super) fn build_final_evidence(
    config: &ResolvedProjectConfig,
    layout: &RunLayout,
    inventory: &CaseGroupInventory,
    state: &mut ActiveRunState,
) -> Result<()> {
    build_final_evidence_from_current_report(config, layout, inventory, state)
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
    let options = ReplayAggregateOptions {
        case_ids: all_case_ids,
        session_ids: BTreeSet::from([session_id.clone()]),
    };
    let aggregate = aggregate_runner_replay_report(
        &layout.case_source,
        &state.replay_report,
        &layout.active_dir,
        &options,
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
mod tests;
