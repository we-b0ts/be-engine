//! Published evidence for an unrelated API remains readable during focused Replay.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

use super::{
    E2eRunContext,
    case_run::status_e2e_run,
    model::{ActiveRunState, RunLayout, RunStatus},
    run_config, store, support,
};

pub(super) fn require_response_reports(state: &ActiveRunState) -> Result<()> {
    for (path, missing) in [
        (
            &state.assertions_report,
            "runner-owned assertion evidence is missing",
        ),
        (
            &state.aggregate_report,
            "runner-owned aggregate evidence is missing",
        ),
    ] {
        require_report(state, path, missing)?;
    }
    Ok(())
}

pub(super) fn require_aggregate_report(state: &ActiveRunState) -> Result<()> {
    require_report(
        state,
        &state.aggregate_report,
        "runner-owned aggregate evidence is missing",
    )
}

fn require_report(state: &ActiveRunState, path: &Path, missing: &str) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    if state.status == RunStatus::Interrupted && !state.replay_finalized {
        let executed = state
            .cases
            .iter()
            .filter(|case| case.assertion_passed.is_some())
            .count();
        let failure = state
            .errors
            .last()
            .map(|error| error.chars().take(512).collect::<String>())
            .unwrap_or_else(|| "no runtime failure was retained".into());
        bail!(
            "{missing}: Replay attempt {} was interrupted before finalization after {executed}/{} executed cases; primary rule planning requires a complete finalized Replay. Resource/global rules may use another completed focused attempt, retaining fresh-Replay obligations for unfinished foreign APIs. Diagnose the runtime failure and follow the coordinator's current action; last failure: {failure}",
            state.sequence,
            state.cases.len()
        );
    }
    bail!("{missing}")
}

pub(super) fn focused_root(layout: &RunLayout, api: &str) -> Result<PathBuf> {
    let root = layout
        .run_root
        .join("focused")
        .join(support::api_directory(api));
    ensure!(
        !root.join(".active").exists(),
        "evidence for API {api:?} is unavailable while its attempt is active"
    );
    if layout.active_dir.exists() {
        ensure_unrelated(&layout.active_dir.join("state.yaml"), api)?;
    }
    Ok(root)
}

fn ensure_unrelated(path: &Path, api: &str) -> Result<()> {
    // Missing/ambiguous startup identity cannot authorize concurrent evidence.
    let active: ActiveRunState = store::read_yaml(path)
        .context("cannot identify active Replay scope for evidence access")?;
    ensure!(
        !active.apis.is_empty() && active.apis.iter().all(|a| a.group_id != api),
        "evidence for API {api:?} is unavailable while its attempt is active"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct E2eResponseRuleEvidence {
    pub replay: PathBuf,
    pub assertions: PathBuf,
    pub aggregate: PathBuf,
}

pub enum OptionalResponseRuleEvidence {
    Absent,
    Unavailable(PathBuf),
    Available(E2eResponseRuleEvidence, PathBuf),
}

/// Foreign APIs without a complete attempt retain an explicit Replay obligation.
/// Known unfinished attempts retain their state identity; malformed complete or
/// active published evidence never becomes absence.
pub fn optional_response_rule_evidence(
    context: E2eRunContext,
    api: &str,
) -> Result<OptionalResponseRuleEvidence> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused = focused_root(&layout, api)?.join("latest/state.yaml");
    let full = layout.latest_dir.join("state.yaml");
    let state_path = if !focused.is_file() {
        if !full.is_file() {
            return Ok(OptionalResponseRuleEvidence::Absent);
        }
        let state: ActiveRunState = store::read_yaml(&full)?;
        if !state.apis.iter().any(|candidate| candidate.group_id == api) {
            return Ok(OptionalResponseRuleEvidence::Absent);
        }
        full
    } else {
        focused
    };
    let state: ActiveRunState = store::read_yaml(&state_path)?;
    ensure!(
        state.status.is_terminal(),
        "foreign Replay evidence is not terminal"
    );
    ensure!(
        state.case_source == layout.case_source
            && state.apis.iter().any(|candidate| candidate.group_id == api),
        "foreign Replay evidence belongs to another recording or API"
    );
    if state.status == RunStatus::Interrupted && !state.replay_finalized
        || state.replay_finalized && !state.aggregate_complete
    {
        return Ok(OptionalResponseRuleEvidence::Unavailable(state_path));
    }
    resolve_e2e_response_rule_evidence(context, api)
        .map(|evidence| OptionalResponseRuleEvidence::Available(evidence, state_path))
}

pub fn resolve_e2e_response_rule_evidence(
    context: E2eRunContext,
    api: &str,
) -> Result<E2eResponseRuleEvidence> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    let focused_root = focused_root(&layout, api)?;
    let focused_state = focused_root.join("latest/state.yaml");
    let full_state = layout.latest_dir.join("state.yaml");
    let state_path = if focused_state.is_file() {
        focused_state
    } else if full_state.is_file() {
        ensure!(
            !layout.active_dir.exists(),
            "full-run evidence is unavailable while an E2E attempt is active"
        );
        full_state
    } else {
        anyhow::bail!(
            "no finalized E2E evidence exists for API {api:?} and case source {}",
            layout.case_source.display()
        );
    };
    let state: ActiveRunState = store::read_yaml(&state_path)?;
    ensure!(
        state.status.is_terminal(),
        "response-rule evidence is not terminal"
    );
    ensure!(
        state.case_source == layout.case_source,
        "response-rule evidence belongs to another case source"
    );
    ensure!(
        state.apis.iter().any(|candidate| candidate.group_id == api),
        "finalized E2E evidence does not contain API {api:?}"
    );
    // Response planners consume the published assertion and aggregate reports.
    // Consumers of the replay report validate it when reading it; do not require
    // that additional artifact for response-only planning.
    require_response_reports(&state)?;
    Ok(E2eResponseRuleEvidence {
        replay: state.replay_report,
        assertions: state.assertions_report,
        aggregate: state.aggregate_report,
    })
}

pub fn ensure_response_rule_evidence_inactive(context: E2eRunContext, api: &str) -> Result<()> {
    let (_, layout) = run_config::resolve_layout(
        &context.target_root,
        &context.case_source,
        context.run_key.as_deref(),
    )?;
    focused_root(&layout, api)?;
    Ok(())
}

pub fn resolve_single_e2e_response_rule_evidence(
    context: E2eRunContext,
) -> Result<E2eResponseRuleEvidence> {
    let status = status_e2e_run(context.clone())?;
    let available = status
        .focused_apis
        .into_iter()
        .filter(|candidate| candidate.status != "not_started")
        .collect::<Vec<_>>();
    ensure!(
        available.len() == 1,
        "process-owned dependency evidence requires exactly one finalized focused API; use the rewrite coordinator when the case source has {} candidates",
        available.len()
    );
    resolve_e2e_response_rule_evidence(context, &available[0].api)
}
