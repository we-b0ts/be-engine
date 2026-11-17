//! Exact-session lookup of published batch and current focused diagnostic reports.
use super::{E2eRunContext, config, evidence_admission, model::*, store};
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct DiagnosticReport {
    pub path: PathBuf,
    pub key_context: PathBuf,
    pub session_id: String,
    pub sequence: u64,
}

pub fn batch_diagnostic_report(
    context: E2eRunContext,
    session: Option<&str>,
) -> Result<DiagnosticReport> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let directory = if let Some(session) = session {
        validate_session(session)?;
        layout.run_root.join("actual-batches").join(session)
    } else {
        layout.latest_dir.clone()
    };
    published(&layout, &directory, session).map(|(_, report)| report)
}

pub fn session_diagnostic_report(
    context: E2eRunContext,
    session: &str,
    focused: Option<(&str, u64)>,
) -> Result<DiagnosticReport> {
    let (_, layout) = config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    session_report(&layout, session, focused)
}

fn session_report(
    layout: &RunLayout,
    session: &str,
    focused: Option<(&str, u64)>,
) -> Result<DiagnosticReport> {
    validate_session(session)?;
    let archive = layout.run_root.join("actual-batches").join(session);
    // A malformed existing archive must fail rather than select another report.
    if archive.exists() || focused.is_none() {
        return published(layout, &archive, Some(session)).map(|(_, report)| report);
    }
    let (api, attempt) = focused.context("current focused attempt absent")?;
    let (state, report) = focused_report(layout, session, api, attempt)?;
    let inventory = crate::case_group::load_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )?;
    let group = inventory
        .groups
        .iter()
        .find(|group| group.group_id == api)
        .context("focused API absent from canonical case inventory")?;
    super::case_selection::validate_group(&state, group)?;
    ensure!(
        state.source_revision == inventory.source_revision,
        "focused Target report belongs to another Source revision"
    );
    Ok(report)
}

fn focused_report(
    layout: &RunLayout,
    session: &str,
    api: &str,
    attempt: u64,
) -> Result<(ActiveRunState, DiagnosticReport)> {
    let directory = evidence_admission::focused_root(layout, api)?.join("latest");
    let (state, report) = published(layout, &directory, Some(session))?;
    ensure!(
        state.sequence == attempt
            && state.apis.iter().any(|candidate| candidate.group_id == api)
            && !state.cases.is_empty()
            && state.cases.iter().all(|case| case.group_id == api),
        "Target report is outside the current focused API attempt"
    );
    Ok((state, report))
}

fn validate_session(session: &str) -> Result<()> {
    ensure!(
        !session.is_empty()
            && session.len() <= 128
            && session
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "invalid actual session selector"
    );
    Ok(())
}

fn published(
    layout: &RunLayout,
    directory: &Path,
    session: Option<&str>,
) -> Result<(ActiveRunState, DiagnosticReport)> {
    let state: ActiveRunState = store::read_yaml(&directory.join("state.yaml"))?;
    let actual = state.session_id.as_ref().context("Target session absent")?;
    ensure!(
        session.is_none_or(|expected| expected == actual),
        "published report belongs to a different actual session"
    );
    ensure!(
        state.status.is_terminal() && state.replay_finalized,
        "Target diagnostic report is not finalized"
    );
    ensure!(
        state.case_source == layout.case_source,
        "Target diagnostic report belongs to another Source recording"
    );
    ensure!(
        state.replay_report == directory.join("reports/replay-report.json"),
        "Target report escaped its published snapshot"
    );
    crate::dependency_index::FileStamp::read_native(&state.replay_report)?;
    let key_context = crate::dependency_index::recording::root(&state.case_source)
        .context("Target report has no central Source key context")?;
    let report = DiagnosticReport {
        path: state.replay_report.clone(),
        key_context,
        session_id: actual.clone(),
        sequence: state.sequence,
    };
    Ok((state, report))
}
