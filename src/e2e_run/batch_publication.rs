//! Archive one real full session once; method snapshots reference its immutable evidence.
use super::{
    E2eRunContext,
    model::{ActiveRunState, CaseStatus, RunLayout, RunStatus},
    store,
    support::api_directory,
};
use crate::case_group::CaseGroupInventory;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::fs;
#[cfg(test)]
mod tests;

pub(super) fn publish(layout: &RunLayout, inventory: &CaseGroupInventory) -> Result<()> {
    let state: ActiveRunState = store::read_yaml(&layout.latest_dir.join("state.yaml"))?;
    if !state.replay_finalized || state.session_id.is_none() {
        return Ok(());
    }
    let report: Value = serde_json::from_slice(&fs::read(&state.replay_report)?)?;
    ensure!(
        report["version"] == 7
            && report["finalized"] == true
            && report["session_id"].as_str() == state.session_id.as_deref(),
        "full-session projection requires its actual finalized report"
    );
    let session = state
        .session_id
        .as_deref()
        .context("actual session absent")?;
    ensure!(
        !session.is_empty()
            && session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "invalid actual session identity"
    );
    let archive = layout.run_root.join("actual-batches").join(session);
    let parent = archive.parent().context("batch archive parent absent")?;
    fs::create_dir_all(parent)?;
    ensure!(
        !archive.exists(),
        "this actual session has already been archived"
    );
    let staging = parent.join(format!(".stage-{}", uuid::Uuid::new_v4().simple()));
    super::focused_batch::copy_evidence(&layout.latest_dir, &staging)?;
    let archived =
        super::assertion_publication::prepare(&state, &layout.latest_dir, &staging, &archive)?;
    store::write_yaml(&staging.join("state.yaml"), &archived)?;
    fs::rename(&staging, &archive)?;
    for group in &inventory.groups {
        let mut projected = super::focused_batch::project(&archived, &group.group_id);
        ensure!(
            !projected.cases.is_empty() && projected.cases.len() == group.cases.len(),
            "actual session projection omits method inputs"
        );
        let root = layout
            .run_root
            .join("focused")
            .join(api_directory(&group.group_id));
        ensure!(
            !root.join(".active").exists(),
            "a method attempt became active during full-session publication"
        );
        let latest = root.join("latest");
        let previous: Option<ActiveRunState> = if latest.join("state.yaml").is_file() {
            Some(store::read_yaml(&latest.join("state.yaml"))?)
        } else {
            None
        };
        projected.sequence = previous
            .map_or(0, |state| state.sequence)
            .checked_add(1)
            .context("method attempt counter overflow")?;
        projected.case_inventory_id = group.case_inventory_id.clone();
        projected
            .errors
            .retain(|error| !error.starts_with("batch dependency reconciliation remains pending:"));
        projected.aggregate_complete = projected.replay_finalized
            && projected.cases.iter().all(|case| {
                matches!(case.status, CaseStatus::Passed | CaseStatus::Failed)
                    && case.replay_clean.is_some()
            });
        projected.aggregate_clean = projected
            .cases
            .iter()
            .all(|case| case.replay_clean == Some(true))
            && report["dependency_hypothesis_coverage_error"].is_null();
        if archived.status != RunStatus::Interrupted {
            projected.status = if projected.aggregate_complete
                && projected.aggregate_clean
                && projected.errors.is_empty()
                && projected.cases.iter().all(|case| {
                    case.status == CaseStatus::Passed && case.assertion_passed == Some(true)
                }) {
                RunStatus::Successful
            } else {
                RunStatus::Failed
            };
        }
        if let Some(api) = projected.apis.first_mut() {
            api.complete_pass = projected.status == RunStatus::Successful;
        }
        let stage = root.join(format!(".batch-stage-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&stage)?;
        store::publish_reference_snapshot(&stage, &latest, &projected)?;
    }
    Ok(())
}

pub(crate) fn latest_batch_api_results(
    context: E2eRunContext,
) -> Result<Vec<super::E2eApiRunResult>> {
    let (_, layout) = super::config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let batch: ActiveRunState = store::read_yaml(&layout.latest_dir.join("state.yaml"))?;
    if !batch.replay_finalized || batch.session_id.is_none() {
        return Ok(vec![]);
    }
    batch
        .apis
        .iter()
        .map(|api| {
            let (state, latest) =
                super::evidence::finalized_focused_evidence(context.clone(), &api.group_id)?;
            ensure!(
                state.session_id == batch.session_id
                    && state.executed_replay_identity == batch.executed_replay_identity,
                "method evidence is not a projection of the latest actual batch session"
            );
            let mut method_layout = layout.clone();
            method_layout.latest_dir = latest;
            Ok(super::result::api_result(
                &method_layout,
                &state,
                &api.group_id,
                state.sequence,
            ))
        })
        .collect()
}

pub(crate) struct DiagnosticBatchReport {
    pub path: std::path::PathBuf,
    pub key_context: std::path::PathBuf,
    pub session_id: String,
    pub sequence: u64,
}

pub(crate) fn batch_diagnostic_report(
    context: E2eRunContext,
    session: Option<&str>,
) -> Result<DiagnosticBatchReport> {
    let (_, layout) = super::config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let directory = if let Some(session) = session {
        ensure!(
            !session.is_empty()
                && session.len() <= 128
                && session
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
            "invalid actual session selector"
        );
        layout.run_root.join("actual-batches").join(session)
    } else {
        layout.latest_dir
    };
    let state: ActiveRunState = store::read_yaml(&directory.join("state.yaml"))?;
    let actual = state
        .session_id
        .context("actual batch has no Target session")?;
    ensure!(
        session.is_none_or(|expected| expected == actual),
        "archive belongs to a different actual session"
    );
    ensure!(
        state.replay_report == directory.join("reports/replay-report.json"),
        "actual batch report escaped its published snapshot"
    );
    crate::dependency_index::FileStamp::read_native(&state.replay_report)?;
    let key_context = crate::dependency_index::recording::root(&state.case_source)
        .context("actual batch has no central Source key context")?;
    Ok(DiagnosticBatchReport {
        path: state.replay_report,
        key_context,
        session_id: actual,
        sequence: state.sequence,
    })
}
