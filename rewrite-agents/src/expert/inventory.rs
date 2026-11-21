//! Project expert lifecycle state and commands for the coordinator.
use super::{
    assignment::{batch_id, due_api, has_active_batch, last_unfinished_api},
    eligibility::eligible_after,
    model::*,
};
use crate::implementer::binding;
use chrono::Utc;
use std::{collections::BTreeMap, path::Path};
use traffic_rewrite_model::rewrite::{
    RewriteCommandSpec, RewriteState, RewriteWorkScope, inventory::is_skipped,
};

type CommandRenderer = fn(&Path, Vec<String>, Vec<String>) -> RewriteCommandSpec;
const HANDLE_ENV: &str = "BACKEND_REWRITE_EXPERT_HANDLE";
const REPORT_ENV: &str = "BACKEND_REWRITE_EXPERT_REPORT_ID";
const RECIPIENT_ENV: &str = "BACKEND_REWRITE_EXPERT_RECIPIENT_HANDLE";
fn command(
    render_command: CommandRenderer,
    root: &Path,
    operation: &str,
    id: &str,
    required: &[&str],
) -> RewriteCommandSpec {
    render_command(
        root,
        vec!["expert".into(), operation.into(), id.into()],
        required.iter().map(|value| (*value).into()).collect(),
    )
}

fn view(
    root: &Path,
    state: &RewriteState,
    id: String,
    apis: Vec<String>,
    kind: RewriteExpertState,
    active_scopes: &[RewriteWorkScope],
    render_command: CommandRenderer,
) -> RewriteExpertInventoryItem {
    let assignment = apis
        .first()
        .and_then(|api| state.worker_bindings[api].expert.as_ref());
    let handle = assignment.and_then(|expert| expert.agent_handle_fingerprint.clone());
    let agent_handle = assignment.and_then(|expert| expert.agent_handle.clone());
    let close_expert = (kind == RewriteExpertState::CloseRequired).then(|| {
        let mut command = command(render_command, root, "close", &id, &[]);
        if let Some(handle) = &agent_handle {
            command
                .argv
                .extend(["--agent-handle".into(), handle.clone()]);
        } else if handle.is_some() {
            command.required_env_names.push(HANDLE_ENV.into());
        }
        command
    });
    let prepare = (kind == RewriteExpertState::PrepareRequired).then(|| {
        let mut command = command(render_command, root, "prepare", &id, &[]);
        for api in &apis {
            command.argv.extend(["--api".into(), api.clone()]);
        }
        command
    });
    let api_views = apis
        .into_iter()
        .map(|api| {
            let binding = &state.worker_bindings[&api];
            let scope = RewriteWorkScope::Api { api: api.clone() };
            let report = binding
                .expert
                .as_ref()
                .and_then(|expert| expert.delivery.as_ref());
            let report_delivered = (kind == RewriteExpertState::Confirmed && report.is_none())
                .then(|| {
                    let mut command = command(
                        render_command,
                        root,
                        "delivered",
                        &id,
                        &[HANDLE_ENV, REPORT_ENV, RECIPIENT_ENV],
                    );
                    command.argv.extend(["--api".into(), api.clone()]);
                    command
                });
            RewriteExpertApiView {
                work_scope: scope.clone(),
                implementer: active_scopes
                    .contains(&scope)
                    .then(|| binding::dispatch_view(state, scope, None)),
                implementer_handle_fingerprint: binding.agent_handle_fingerprint.clone(),
                first_bound_at: binding.first_bound_at.clone(),
                last_integrated_at: binding.last_integrated_at.clone(),
                last_integrated_commit: binding.last_integrated_commit.clone(),
                eligible_after: eligible_after(binding).map(|value| value.to_rfc3339()),
                worktree: binding
                    .review_assignment
                    .as_ref()
                    .map(|assignment| assignment.worktree.clone()),
                report_id: report.map(|delivery| delivery.report_id.clone()),
                commands: RewriteExpertApiCommands {
                    evidence: render_command(
                        root,
                        vec!["evidence".into(), "--api".into(), api],
                        vec![],
                    ),
                    report_delivered,
                },
            }
        })
        .collect();
    RewriteExpertInventoryItem {
        expert: RewriteExpertView {
            expert_id: id.clone(),
            role: "api-expert",
            state: kind,
            apis: api_views,
            agent_handle_fingerprint: handle,
            agent_handle,
            closed_at: assignment.and_then(|expert| expert.closed_at.clone()),
        },
        commands: RewriteExpertCommands {
            prepare,
            confirm_expert: (kind == RewriteExpertState::DispatchRequired
                || (kind == RewriteExpertState::CloseRequired
                    && assignment.is_some_and(|expert| expert.agent_handle_fingerprint.is_none())))
            .then(|| command(render_command, root, "confirm", &id, &[HANDLE_ENV])),
            close_expert,
        },
    }
}

pub fn inventory(
    root: &Path,
    state: &RewriteState,
    active_scopes: &[RewriteWorkScope],
    verified: fn(&RewriteState, &str) -> bool,
    render_command: CommandRenderer,
) -> Vec<RewriteExpertInventoryItem> {
    let mut batches = BTreeMap::new();
    for binding in state.worker_bindings.values() {
        if let Some(expert) = &binding.expert {
            batches
                .entry(expert.id.clone())
                .or_insert_with(|| expert.apis.clone());
        }
    }

    let mut result = Vec::new();
    for (id, apis) in batches {
        if apis.iter().all(|api| is_skipped(state, api)) {
            continue;
        }
        let first = state.worker_bindings[&apis[0]].expert.as_ref().unwrap();
        let kind = if apis.iter().all(|api| {
            state.worker_bindings[api]
                .expert
                .as_ref()
                .unwrap()
                .closed_at
                .is_some()
        }) {
            RewriteExpertState::Closed
        } else if apis.iter().all(|api| {
            state.worker_bindings[api]
                .expert
                .as_ref()
                .unwrap()
                .delivery
                .is_some()
        }) {
            RewriteExpertState::Delivered
        } else if apis.iter().all(|api| verified(state, api)) {
            RewriteExpertState::CloseRequired
        } else if first.agent_handle_fingerprint.is_some() {
            RewriteExpertState::Confirmed
        } else if !apis.iter().all(|api| last_unfinished_api(state, api)) {
            RewriteExpertState::NotDue
        } else {
            RewriteExpertState::DispatchRequired
        };
        result.push(view(
            root,
            state,
            id,
            apis,
            kind,
            active_scopes,
            render_command,
        ));
    }
    if !has_active_batch(state)
        && let Some(api) = due_api(state, Utc::now(), active_scopes.iter().cloned())
    {
        let apis = vec![api];
        result.push(view(
            root,
            state,
            batch_id(state, &apis),
            apis,
            RewriteExpertState::PrepareRequired,
            active_scopes,
            render_command,
        ));
    }
    result
}
