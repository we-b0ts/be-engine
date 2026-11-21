//! Bind compact diagnostics to the implementer's original work scope.
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use traffic_rewrite_evidence::evidence::implementer;

use super::super::{api_selector, inventory, model::RewriteState, worker};
use super::RewriteWorkScope;

#[derive(Debug, Serialize)]
pub struct ImplementerEvidence {
    schema_version: u32,
    api: String,
    assignment: Assignment,
    attempts: Vec<Value>,
    failures: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct Assignment {
    workflow_id: String,
    recording_run_id: String,
    binding_id: String,
    dispatch_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktree: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_handle: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_repairs: Vec<traffic_rewrite_model::rewrite::review::model::ReviewFinding>,
}

pub(super) fn report(
    root: &Path,
    state: &RewriteState,
    selected: &RewriteState,
    scope: &RewriteWorkScope,
) -> Result<ImplementerEvidence> {
    let RewriteWorkScope::Api { api } = scope;
    let mut report = ImplementerEvidence {
        schema_version: 1,
        api: api.clone(),
        assignment: assignment(root, selected, scope),
        attempts: Vec::new(),
        failures: Vec::new(),
    };
    let mut append = |state: &RewriteState| {
        if let Some(issue) = &state.active_issue {
            let evidence = implementer::method(root, state, issue);
            report.attempts.push(evidence.attempt);
            report.failures.extend(evidence.failures);
        }
    };
    append(selected);
    for method in api_selector::members(state, &api.parse()?) {
        if method != selected.api
            && let Ok(sibling) = inventory::scoped(state, Some(&method.parse()?))
            && sibling.phase == crate::RewritePhase::ImplementationRequired
        {
            append(&sibling);
        }
    }
    Ok(report)
}

fn assignment(root: &Path, state: &RewriteState, scope: &RewriteWorkScope) -> Assignment {
    let dispatch = worker::dispatch_view(state, scope.clone(), None);
    let delivery = crate::review::context(root, state, scope);
    let (worktree, base_revision) = delivery
        .assignment
        .map(|assignment| (Some(assignment.worktree), Some(assignment.base_revision)))
        .unwrap_or_default();
    let scope_key = scope.binding_key();
    let pooled = state.implementers.as_ref().and_then(|pool| {
        pool.slots.iter().find_map(|(&slot, worker)| {
            let task = worker.tasks.get(&scope_key)?;
            (task.dispatch_id == dispatch.dispatch_id
                && task.recording_run_id == state.recording_run_id)
                .then_some((slot, task.lease_generation))
        })
    });
    Assignment {
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        binding_id: dispatch.binding_id,
        dispatch_id: dispatch.dispatch_id,
        worktree,
        base_revision,
        slot: pooled.map(|(slot, _)| slot),
        lease_generation: pooled.map(|(_, lease)| lease),
        agent_handle: dispatch.agent_handle,
        required_repairs: delivery
            .required_repairs
            .map(|repairs| repairs.findings.into_values().collect())
            .unwrap_or_default(),
    }
}
