//! Engine-owned API assistance timing and serialized diagnostic batches. The
//! coordinator submits one runtime task per batch and forwards per-API reports.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteApiStatus, RewritePhase, RewriteState,
};
use super::{RewriteWorkScope, action, fingerprint, store::RewriteStore, worker};

pub(super) mod model;
use model::*;

const EXPERT_AFTER_SECONDS: i64 = 2 * 60 * 60;
const HANDLE_ENV: &str = "BACKEND_REWRITE_EXPERT_HANDLE";
const REPORT_ENV: &str = "BACKEND_REWRITE_EXPERT_REPORT_ID";
const RECIPIENT_ENV: &str = "BACKEND_REWRITE_EXPERT_RECIPIENT_HANDLE";

fn batch_id(state: &RewriteState, apis: &[String]) -> String {
    fingerprint::id(&[
        "rewrite-api-expert-batch-v1",
        &state.workflow_id,
        &serde_json::to_string(apis).expect("API list serializes"),
    ])
}

fn unfinished(state: &RewriteState, api: &str) -> bool {
    state
        .api_inventory
        .iter()
        .find(|item| item.api == api)
        .map_or_else(
            || {
                state.api_inventory.is_empty()
                    && state.api == api
                    && state.phase != RewritePhase::SliceComplete
            },
            |item| !item.status.is_done(),
        )
}

fn eligible_after(binding: &worker::model::RewriteWorkerBinding) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(
        binding
            .last_integrated_at
            .as_deref()
            .or(binding.first_bound_at.as_deref())?,
    )
    .ok()?
    .with_timezone(&Utc)
    .checked_add_signed(Duration::seconds(EXPERT_AFTER_SECONDS))
}

fn state_at(
    binding: &worker::model::RewriteWorkerBinding,
    now: DateTime<Utc>,
) -> RewriteExpertState {
    match &binding.expert {
        Some(expert) if expert.closed_at.is_some() => RewriteExpertState::Closed,
        Some(expert) if expert.delivery.is_some() => RewriteExpertState::Delivered,
        Some(expert) if expert.agent_handle_fingerprint.is_some() => RewriteExpertState::Confirmed,
        Some(_) => RewriteExpertState::DispatchRequired,
        None => match eligible_after(binding) {
            None => RewriteExpertState::NotDue,
            Some(after) if now > after => RewriteExpertState::PrepareRequired,
            Some(_) => RewriteExpertState::NotDue,
        },
    }
}

/// Count actual running API workers. Unknown/unconfirmed runtime states require
/// reconciliation before concluding that a worker is alone. Queued and ended
/// workers do not count as running; delivered historical bindings are ignored.
fn due_api(state: &RewriteState, now: DateTime<Utc>) -> Option<String> {
    use worker::model::{
        RewriteWorkerActivity as Activity, RewriteWorkerCoverageState as Coverage,
    };
    let mut running = None;
    for scope in worker::runtime::scopes(state) {
        let RewriteWorkScope::Api { ref api } = scope else {
            continue;
        };
        if !unfinished(state, api) {
            continue;
        }
        let observation = worker::runtime::observation(state, &scope);
        match worker::runtime::coverage(state, &scope) {
            Coverage::StatusRequired | Coverage::DispatchRequired => return None,
            Coverage::ResumeRequired => {
                if !observation.is_some_and(|value| {
                    matches!(value.activity, Activity::Idle | Activity::ReworkRequired)
                }) {
                    return None;
                }
            }
            Coverage::Running
                if observation.is_some_and(|value| value.activity == Activity::Running) =>
            {
                let previous = running.replace(api.clone());
                if previous.is_some() {
                    return None;
                }
            }
            _ => {}
        }
    }
    let api = running?;
    (state_at(state.worker_bindings.get(&api)?, now) == RewriteExpertState::PrepareRequired)
        .then_some(api)
}

fn command(root: &Path, operation: &str, id: &str, required: &[&str]) -> super::RewriteCommandSpec {
    action::command(
        root,
        vec!["expert".into(), operation.into(), id.into()],
        required.iter().map(|value| (*value).into()).collect(),
    )
}

fn has_active_batch(state: &RewriteState) -> bool {
    state.worker_bindings.values().any(|binding| {
        binding
            .expert
            .as_ref()
            .is_some_and(|expert| expert.delivery.is_none() && expert.closed_at.is_none())
    })
}

fn batch_apis(state: &RewriteState, id: &str) -> Result<Vec<String>> {
    state
        .worker_bindings
        .values()
        .filter_map(|binding| binding.expert.as_ref())
        .find(|expert| expert.id == id)
        .map(|expert| expert.apis.clone())
        .context("expert batch is not prepared or belongs to another workflow; inspect inventory")
}

fn view(
    root: &Path,
    state: &RewriteState,
    id: String,
    apis: Vec<String>,
    kind: RewriteExpertState,
) -> RewriteExpertInventoryItem {
    let assignment = apis
        .first()
        .and_then(|api| state.worker_bindings[api].expert.as_ref());
    let handle = assignment.and_then(|expert| expert.agent_handle_fingerprint.clone());
    let agent_handle = assignment.and_then(|expert| expert.agent_handle.clone());
    let close_expert = (kind == RewriteExpertState::CloseRequired).then(|| {
        let mut command = command(root, "close", &id, &[]);
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
        let mut command = command(root, "prepare", &id, &[]);
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
                implementer: worker::runtime::scopes(state)
                    .contains(&scope)
                    .then(|| worker::dispatch_view(state, scope, None)),
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
                    evidence: action::command(
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
            .then(|| command(root, "confirm", &id, &[HANDLE_ENV])),
            close_expert,
        },
    }
}

pub(super) fn inventory(root: &Path, state: &RewriteState) -> Vec<RewriteExpertInventoryItem> {
    let mut batches = BTreeMap::new();
    for (api, binding) in &state.worker_bindings {
        if api.starts_with("process_output:") {
            continue;
        }
        if let Some(expert) = &binding.expert {
            batches
                .entry(expert.id.clone())
                .or_insert_with(|| expert.apis.clone());
        }
    }

    let mut result = Vec::new();
    for (id, apis) in batches {
        if apis
            .iter()
            .all(|api| super::regression_scope::is_skipped(state, api))
        {
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
        } else {
            RewriteExpertState::DispatchRequired
        };
        result.push(view(root, state, id, apis, kind));
    }
    if !has_active_batch(state)
        && let Some(api) = due_api(state, Utc::now())
    {
        let apis = vec![api];
        result.push(view(
            root,
            state,
            batch_id(state, &apis),
            apis,
            RewriteExpertState::PrepareRequired,
        ));
    }
    result
}

pub(super) fn required_action(
    root: &Path,
    state: &RewriteState,
    api: Option<&str>,
) -> Option<RewriteAction> {
    let item = inventory(root, state)
        .into_iter()
        .filter(|item| {
            api.is_none_or(|api| {
                item.expert
                    .apis
                    .iter()
                    .any(|item| item.work_scope.binding_key() == api)
            }) && matches!(
                item.expert.state,
                RewriteExpertState::PrepareRequired
                    | RewriteExpertState::DispatchRequired
                    | RewriteExpertState::CloseRequired
            )
        })
        .min_by_key(|item| match item.expert.state {
            RewriteExpertState::CloseRequired => 0,
            RewriteExpertState::DispatchRequired => 1,
            _ => 2,
        })?;
    let summary = match item.expert.state {
        RewriteExpertState::CloseRequired => "the assigned API has passed verification. Do not dispatch or resume an expert. Query the retained expert task; stop it if still running or queued, and confirm it has ended before executing commands.close_expert. If an accepted task was not yet confirmed, recover it and use commands.confirm_expert first; if no task was submitted, close the reservation directly. Retain late findings as reference only; do not forward them as new API work. Closing releases the expert slot and preserves one-time coverage",
        RewriteExpertState::PrepareRequired => "exactly one API worker is running and more than two hours have passed since its last integrated code delivery (or first binding before any code integration). Execute commands.prepare to reserve them as one diagnostic batch. Do not create an expert until the reserved batch returns dispatch_required",
        _ => "dispatch exactly one api-expert for all APIs in details.apis. Recover any existing task for expert_id before submitting; never dispatch twice. The expert uses each API's commands.evidence and worktree read-only and returns per-API findings to the coordinator. Confirm the accepted task, including queued tasks, through commands.confirm_expert. Continue engine work; forward each API's report to its retained implementer and acknowledge each delivery through inventory.experts[].apis[].commands.report_delivered",
    }.to_string();
    Some(RewriteAction::ExpertRequired {
        summary,
        expert: item.expert,
        commands: item.commands,
    })
}

pub(super) fn counts(state: &RewriteState) -> (usize, usize, usize) {
    let items = inventory(Path::new("."), state);
    let mut counts = (0, 0, 0);
    for item in items {
        match item.expert.state {
            RewriteExpertState::PrepareRequired | RewriteExpertState::DispatchRequired => {
                counts.0 += 1
            }
            RewriteExpertState::Confirmed => counts.1 += 1,
            RewriteExpertState::CloseRequired => counts.2 += 1,
            _ => {}
        }
    }
    counts
}

pub fn prepare(options: RewriteExpertPrepareOptions) -> Result<RewriteActionEnvelope> {
    crate::rewrite::purpose::require_work_branch(&options.target_root)?;
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let apis: Vec<_> = options
        .apis
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ensure!(
        !apis.is_empty() && apis.len() == options.apis.len(),
        "expert batch requires distinct APIs"
    );
    ensure!(
        batch_id(&state, &apis) == options.expert_id,
        "expert batch id is stale or does not match its API list"
    );
    if let Ok(existing) = batch_apis(&state, &options.expert_id) {
        ensure!(
            existing == apis,
            "expert batch API list differs from its reservation"
        );
    } else {
        ensure!(
            !has_active_batch(&state),
            "an expert batch is already active; finish its report deliveries before preparing another"
        );
        let now = Utc::now();
        ensure!(
            apis.len() == 1 && due_api(&state, now).as_ref() == apis.first(),
            "expert preparation requires the sole running API worker to be overdue and not already covered; inspect status"
        );
        for api in &apis {
            state.worker_bindings.get_mut(api).unwrap().expert = Some(ExpertAssignment {
                id: options.expert_id.clone(),
                apis: apis.clone(),
                prepared_at: now.to_rfc3339(),
                agent_handle_fingerprint: None,
                agent_handle: None,
                confirmed_at: None,
                closed_at: None,
                delivery: None,
            });
        }
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn confirm(options: RewriteExpertOptions) -> Result<RewriteActionEnvelope> {
    crate::rewrite::purpose::require_work_branch(&options.target_root)?;
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    worker::validate_identity("expert handle", &options.agent_handle, 4096)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let apis = batch_apis(&state, &options.expert_id)?;
    ensure!(
        state.worker_bindings[&apis[0]]
            .expert
            .as_ref()
            .unwrap()
            .closed_at
            .is_none(),
        "expert assignment is closed; do not dispatch or resume it"
    );
    let handle = handle_fingerprint(&options.agent_handle);
    if let Some(existing) = state.worker_bindings[&apis[0]]
        .expert
        .as_ref()
        .unwrap()
        .agent_handle_fingerprint
        .as_ref()
    {
        ensure!(
            existing == &handle,
            "this batch already has its one expert; recover the accepted runtime handle"
        );
    } else {
        ensure!(
            !state.worker_bindings.values().any(|binding| {
                binding.agent_handle_fingerprint == handle
                    || binding.expert.as_ref().is_some_and(|expert| {
                        expert.agent_handle_fingerprint.as_ref() == Some(&handle)
                    })
            }),
            "expert must use its own runtime task, separate from implementers and other batches"
        );
        let now = Utc::now().to_rfc3339();
        for api in &apis {
            let expert = state
                .worker_bindings
                .get_mut(api)
                .unwrap()
                .expert
                .as_mut()
                .unwrap();
            expert.agent_handle_fingerprint = Some(handle.clone());
            expert.agent_handle = Some(options.agent_handle.clone());
            expert.confirmed_at = Some(now.clone());
        }
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

pub fn delivered(options: RewriteExpertDeliveryOptions) -> Result<RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&options.expert.target_root)?;
    worker::validate_identity("expert handle", &options.expert.agent_handle, 4096)?;
    worker::validate_identity("expert report id", &options.report_id, 4096)?;
    worker::validate_identity("report recipient handle", &options.recipient_handle, 4096)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let apis = batch_apis(&state, &options.expert.expert_id)?;
    ensure!(
        apis.contains(&options.api),
        "API does not belong to this expert batch"
    );
    let binding = state.worker_bindings.get_mut(&options.api).unwrap();
    let expert = binding.expert.as_mut().unwrap();
    ensure!(
        expert.agent_handle_fingerprint.as_ref()
            == Some(&handle_fingerprint(&options.expert.agent_handle)),
        "expert handle is unconfirmed or does not match the accepted assignment"
    );
    if expert.closed_at.is_some() || verified(&state, &options.api) {
        drop(lock);
        return worker::runtime::current_envelope(&root);
    }
    let binding = state.worker_bindings.get_mut(&options.api).unwrap();
    let expert = binding.expert.as_mut().unwrap();
    let recipient = handle_fingerprint(&options.recipient_handle);
    if let Some(delivery) = &expert.delivery {
        ensure!(
            delivery.report_id == options.report_id
                && delivery.recipient_handle_fingerprint == recipient,
            "a different expert report delivery is already recorded"
        );
    } else {
        ensure!(
            binding.agent_handle_fingerprint == recipient,
            "expert report must be forwarded to this API's retained implementer"
        );
        expert.delivery = Some(ExpertDelivery {
            report_id: options.report_id,
            recipient_handle_fingerprint: recipient,
            delivered_at: Utc::now().to_rfc3339(),
        });
        worker::events::publish(&root, &state, &RewriteWorkScope::Api { api: options.api })?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

fn verified(state: &RewriteState, api: &str) -> bool {
    state
        .api_inventory
        .iter()
        .any(|item| item.api == api && item.status == RewriteApiStatus::Complete)
}

/// Acknowledge runtime termination (or a reservation that never spawned a task).
/// The engine owns eligibility; only the coordinator can observe runtime exit.
pub fn close(options: RewriteExpertCloseOptions) -> Result<RewriteActionEnvelope> {
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    if let Some(handle) = &options.agent_handle {
        worker::validate_identity("expert handle", handle, 4096)?;
    }
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let apis = batch_apis(&state, &options.expert_id)?;
    let expert = state.worker_bindings[&apis[0]].expert.as_ref().unwrap();
    ensure!(
        expert.agent_handle_fingerprint == options.agent_handle.as_deref().map(handle_fingerprint),
        "close requires the confirmed expert handle; confirm an accepted task before closing it"
    );
    if !apis.iter().all(|api| {
        state.worker_bindings[api]
            .expert
            .as_ref()
            .unwrap()
            .closed_at
            .is_some()
    }) {
        ensure!(
            apis.iter().all(|api| verified(&state, api)),
            "expert close requires the assigned API to have passed verification; follow the current action"
        );
        let now = Utc::now().to_rfc3339();
        for api in &apis {
            state
                .worker_bindings
                .get_mut(api)
                .unwrap()
                .expert
                .as_mut()
                .unwrap()
                .closed_at = Some(now.clone());
        }
        publish_batch(&root, &state, &apis)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}

fn publish_batch(root: &Path, state: &RewriteState, apis: &[String]) -> Result<()> {
    worker::events::publish_many(
        root,
        state,
        &apis
            .iter()
            .map(|api| RewriteWorkScope::Api { api: api.clone() })
            .collect::<Vec<_>>(),
    )
}

fn handle_fingerprint(handle: &str) -> String {
    fingerprint::id(&["rewrite-subagent-handle-v1", handle])
}

#[cfg(test)]
mod tests;
