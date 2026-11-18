//! Expert batch identity, outstanding assignments and dispatch eligibility.
use crate::{api_selector, fingerprint, implementer::feedback};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use traffic_rewrite_model::rewrite::{RewritePhase, RewriteState, RewriteWorkScope};
pub fn batch_id(state: &RewriteState, apis: &[String]) -> String {
    fingerprint::id(&[
        "rewrite-api-expert-batch-v1",
        &state.workflow_id,
        &serde_json::to_string(apis).expect("API list serializes"),
    ])
}

fn unfinished(state: &RewriteState, api: &str) -> bool {
    state.api_inventory.iter().any(|item| {
        (item.api == api || api_selector::route(&item.api) == api) && !item.status.is_done()
    }) || (state.api_inventory.is_empty()
        && api_selector::public_api(&state.api) == api
        && state.phase != RewritePhase::SliceComplete)
}

pub fn last_unfinished_api(state: &RewriteState, api: &str) -> bool {
    unfinished(state, api)
        && state
            .api_inventory
            .iter()
            .all(|item| item.status.is_done() || api_selector::public_api(&item.api) == api)
}

use super::eligibility::state_at;
use super::model::{
    ExpertAssignment, ExpertDelivery, RewriteExpertCloseOptions, RewriteExpertDeliveryOptions,
    RewriteExpertOptions, RewriteExpertPrepareOptions, RewriteExpertState,
};

/// Assist only the last unfinished API, with one actual running implementer.
/// Unknown/unconfirmed runtime states require reconciliation first. Queued and
/// ended workers do not count as running; historical bindings are ignored.
pub fn due_api(
    state: &RewriteState,
    now: DateTime<Utc>,
    scopes: impl IntoIterator<Item = RewriteWorkScope>,
) -> Option<String> {
    use traffic_rewrite_model::rewrite::{
        RewriteWorkerActivity as Activity, RewriteWorkerCoverageState as Coverage,
    };
    let mut running = None;
    for scope in scopes {
        let RewriteWorkScope::Api { ref api } = scope;
        if !unfinished(state, api) {
            continue;
        }
        let observation = feedback::observation(state, &scope);
        match feedback::coverage(state, &scope) {
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
    if !last_unfinished_api(state, &api) {
        return None;
    }
    (state_at(state.worker_bindings.get(&api)?, now) == RewriteExpertState::PrepareRequired)
        .then_some(api)
}

pub fn has_active_batch(state: &RewriteState) -> bool {
    state.worker_bindings.values().any(|binding| {
        binding
            .expert
            .as_ref()
            .is_some_and(|expert| expert.delivery.is_none() && expert.closed_at.is_none())
    })
}

pub fn batch_apis(state: &RewriteState, id: &str) -> Result<Vec<String>> {
    state
        .worker_bindings
        .values()
        .filter_map(|binding| binding.expert.as_ref())
        .find(|expert| expert.id == id)
        .map(|expert| expert.apis.clone())
        .context("expert batch is not prepared or belongs to another workflow; inspect inventory")
}

pub fn prepare(
    state: &mut RewriteState,
    options: &RewriteExpertPrepareOptions,
    scopes: impl IntoIterator<Item = RewriteWorkScope>,
) -> Result<Option<Vec<String>>> {
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
        batch_id(state, &apis) == options.expert_id,
        "expert batch id is stale or does not match its API list"
    );
    if let Ok(existing) = batch_apis(state, &options.expert_id) {
        ensure!(
            existing == apis,
            "expert batch API list differs from its reservation"
        );
    } else {
        ensure!(
            !has_active_batch(state),
            "an expert batch is already active; finish its report deliveries before preparing another"
        );
        let now = Utc::now();
        ensure!(
            apis.len() == 1 && due_api(state, now, scopes).as_ref() == apis.first(),
            "expert preparation requires the last unfinished API's sole running implementer to be overdue and not already covered; inspect status"
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
        return Ok(Some(apis));
    }
    Ok(None)
}

pub fn confirm(
    state: &mut RewriteState,
    options: &RewriteExpertOptions,
) -> Result<Option<Vec<String>>> {
    let apis = batch_apis(state, &options.expert_id)?;
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
        return Ok(Some(apis));
    }
    Ok(None)
}

pub fn delivered(
    state: &mut RewriteState,
    options: RewriteExpertDeliveryOptions,
    verified: fn(&RewriteState, &str) -> bool,
) -> Result<Option<Vec<String>>> {
    let apis = batch_apis(state, &options.expert.expert_id)?;
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
    if expert.closed_at.is_some() || verified(state, &options.api) {
        return Ok(None);
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
        return Ok(Some(vec![options.api]));
    }
    Ok(None)
}

pub fn close(
    state: &mut RewriteState,
    options: &RewriteExpertCloseOptions,
    verified: fn(&RewriteState, &str) -> bool,
) -> Result<Option<Vec<String>>> {
    let apis = batch_apis(state, &options.expert_id)?;
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
            apis.iter().all(|api| verified(state, api)),
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
        return Ok(Some(apis));
    }
    Ok(None)
}

pub fn handle_fingerprint(handle: &str) -> String {
    fingerprint::id(&["rewrite-subagent-handle-v1", handle])
}
