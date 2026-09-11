use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};

use super::super::model::{RewriteActionEnvelope, RewritePhase, RewriteState};
use super::super::process_output_model::{RewriteProcessOutputStatus, RewriteWorkScope};
use super::super::{action, fingerprint, inventory, process_outputs, store::RewriteStore};
use super::model::{RewriteWorkerActivity, RewriteWorkerCoverageState, RewriteWorkerObservation};

pub(in crate::rewrite) const RUNNING_OBSERVATION_SECONDS: i64 = 60 * 60;
pub(in crate::rewrite) const ACTIVITY_ENV: &str = "BACKEND_REWRITE_WORKER_ACTIVITY";
pub(in crate::rewrite) const HANDOFF_ENV: &str = "BACKEND_REWRITE_WORKER_HANDOFF_ID";

#[derive(Debug, Clone)]
pub struct RewriteWorkerReportOptions {
    pub target_root: PathBuf,
    pub agent_handle: String,
    pub activity: RewriteWorkerActivity,
    pub handoff_id: Option<String>,
    pub review_report: Option<PathBuf>,
}

pub fn report(options: RewriteWorkerReportOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    super::validate_identity("subagent handle", &options.agent_handle, 4096)?;
    let store = RewriteStore::new(&target_root)?;
    let integration_lock = if matches!(
        options.activity,
        RewriteWorkerActivity::Integrated | RewriteWorkerActivity::ReworkRequired
    ) {
        let lock = store.try_lock()?.context(
            "integration must wait for the current verification or coordinator transition",
        )?;
        ensure!(
            matches!(
                super::super::traffic_operation::state(&target_root)?,
                super::super::traffic_operation::TrafficOperationState::Absent
            ),
            "integration must wait for the current traffic operation"
        );
        Some(lock)
    } else {
        None
    };
    let _lock = super::events::lock(&target_root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scope = super::identity::report_scope(&state, &options)?;
    let target_fingerprint = (options.activity == RewriteWorkerActivity::Integrated)
        .then(|| fingerprint::repository_fingerprint(&target_root))
        .transpose()?;
    let review = if options.activity == RewriteWorkerActivity::HandoffReady {
        let duplicate = observation(&state, &scope).is_some_and(|o| {
            o.handoff_id == options.handoff_id
                && matches!(
                    o.activity,
                    RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                )
        });
        if duplicate {
            None
        } else {
            Some(super::super::review::accept_handoff(
                &target_root,
                &state,
                &scope,
                options.review_report.as_deref(),
            )?)
        }
    } else {
        None
    };
    let mut changed = apply_report(&mut state, &scope, &options, target_fingerprint)?;
    let integration_received = changed && options.activity == RewriteWorkerActivity::Integrated;
    if integration_received {
        let path = options.review_report.as_deref().context("integrated delivery requires --review-report from code-integrator review check --integration")?;
        let code_commit = super::super::review::accept_integration(
            &target_root,
            &mut state,
            path,
            Some(&scope),
            options.handoff_id.as_deref(),
        )?;
        if let Some(commit) = code_commit {
            let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
            if binding.last_integrated_commit.as_ref() != Some(&commit) {
                binding.last_integrated_commit = Some(commit);
                binding.last_integrated_at = Some(Utc::now().to_rfc3339());
            }
        }
    }

    if let Some(review) = review {
        state
            .worker_bindings
            .get_mut(&scope.binding_key())
            .unwrap()
            .review_report = Some(review);
    }
    let rework_finished = changed
        && options.activity == RewriteWorkerActivity::Integrated
        && state
            .source_review_rework
            .remove(&scope.binding_key())
            .is_some();
    if rework_finished {
        state.bump();
    }
    let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
    if binding.agent_handle.as_deref() != Some(&options.agent_handle) {
        binding.agent_handle = Some(options.agent_handle.clone());
        changed = true;
    }
    if changed {
        super::events::publish(&target_root, &state, &scope)?;
    }
    // A worker report never activates a slice or starts a traffic operation.
    // Recover the global action through status, which also honors live leases.
    drop(_lock);
    if rework_finished || integration_received {
        // Integration holds the coordinator lock. Save only after releasing the
        // feedback lock, because save folds in newer worker observations itself.
        store.save(&state)?;
    }
    drop(integration_lock);
    current_envelope(&target_root)
}

pub(in crate::rewrite) fn current_envelope(target_root: &Path) -> Result<RewriteActionEnvelope> {
    let status = super::super::status_rewrite(super::super::RewriteContext {
        target_root: target_root.to_path_buf(),
    })?;
    Ok(RewriteActionEnvelope {
        schema_version: status.schema_version,
        pending: status.pending,
        workflow: status.workflow,
        api_inventory: status.api_inventory,
        process_output_inventory: status.process_output_inventory,
        latest_focused_e2e: status.latest_focused_e2e,
        action: status.action,
        terminal_allowed: status.terminal_allowed,
    })
}

fn apply_report(
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
    options: &RewriteWorkerReportOptions,
    target_fingerprint: Option<String>,
) -> Result<bool> {
    let binding = state.worker_bindings.get(&scope.binding_key()).context(
        "worker report requires an existing dedicated binding; dispatch and confirm first",
    )?;
    ensure!(
        binding.agent_handle_fingerprint
            == fingerprint::id(&["rewrite-subagent-handle-v1", &options.agent_handle]),
        "worker report handle does not own this work item"
    );
    ensure!(
        binding.confirmed_dispatch_id == super::dispatch_id(state, scope),
        "worker report requires confirmation of the current dispatch"
    );
    let previous = observation(state, scope);
    // Duplicate callbacks are harmless, including a repeated handoff after integration.
    if previous.is_some_and(|value| {
        value.handoff_id == options.handoff_id
            && ((value.activity == options.activity
                && options.activity != RewriteWorkerActivity::Running
                && options.activity != RewriteWorkerActivity::Queued)
                || (value.activity == RewriteWorkerActivity::Integrated
                    && options.activity == RewriteWorkerActivity::HandoffReady))
    }) {
        return Ok(false);
    }
    match options.activity {
        RewriteWorkerActivity::Running | RewriteWorkerActivity::Queued => {
            ensure!(
                !previous.is_some_and(|value| value.activity == RewriteWorkerActivity::Idle),
                "resume the idle worker and execute confirm_worker before reporting it running"
            );
            ensure!(
                !previous.is_some_and(|value| matches!(
                    value.activity,
                    RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                )),
                "a handed-off dispatch cannot become running without a new repair dispatch"
            );
            ensure!(
                options.handoff_id.is_none(),
                "running reports do not accept a handoff id"
            );
        }
        RewriteWorkerActivity::Idle => {
            ensure!(
                !previous.is_some_and(|value| matches!(
                    value.activity,
                    RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                )),
                "retain the ready handoff instead of reporting its worker idle"
            );
            ensure!(
                options.handoff_id.is_none(),
                "idle reports do not accept a handoff id"
            );
            supersede_dispatch(state, scope)?;
        }
        RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated => {
            let handoff = options
                .handoff_id
                .as_deref()
                .context("worker handoff id is required")?;
            super::validate_identity("worker handoff id", handoff, 512)?;
            if options.activity == RewriteWorkerActivity::Integrated {
                ensure!(
                    previous.is_some_and(|value| matches!(
                        value.activity,
                        RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                    ) && value.handoff_id.as_deref() == Some(handoff)),
                    "report the same handoff_ready before acknowledging its integration"
                );
            } else {
                ensure!(
                    !previous
                        .is_some_and(|value| value.activity == RewriteWorkerActivity::Integrated),
                    "an integrated handoff cannot return to handoff_ready"
                );
            }
        }
        RewriteWorkerActivity::ReworkRequired => {
            ensure!(
                previous.is_some_and(|value| matches!(
                    value.activity,
                    RewriteWorkerActivity::HandoffReady | RewriteWorkerActivity::Integrated
                ) && value.handoff_id.is_some()
                    && value.handoff_id == options.handoff_id),
                "rework requires the current handoff identity and a free verification resource"
            );
            supersede_dispatch(state, scope)?;
        }
    }
    let observation = RewriteWorkerObservation {
        dispatch_id: super::dispatch_id(state, scope),
        recording_run_id: state.recording_run_id.clone(),
        activity: options.activity,
        observed_at: Utc::now().to_rfc3339(),
        coordinator_reported: true,
        handoff_id: options.handoff_id.clone(),
        integrated_target_fingerprint: target_fingerprint,
    };
    let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
    // Legacy bindings start their timer on the first accepted observation in
    // this version. Never infer a timestamp from runtime text or Git dates.
    binding
        .first_bound_at
        .get_or_insert_with(|| observation.observed_at.clone());
    binding.observation = Some(observation);
    Ok(true)
}

fn supersede_dispatch(state: &mut RewriteState, scope: &RewriteWorkScope) -> Result<()> {
    let binding = state.worker_bindings.get_mut(&scope.binding_key()).unwrap();
    binding.rework_generation = binding
        .rework_generation
        .checked_add(1)
        .context("worker rework generation overflow")?;
    Ok(())
}

pub(in crate::rewrite) fn scopes(state: &RewriteState) -> Vec<RewriteWorkScope> {
    let mut scopes = Vec::new();
    if !super::super::regression_scope::is_skipped(state, &state.api)
        && state.phase == RewritePhase::ImplementationRequired
        && state.active_issue.is_some()
        && !state.system_repair_accepted
    {
        scopes.push(RewriteWorkScope::Api {
            api: state.api.clone(),
        });
    }
    for (api, slice) in &state.parked_slices {
        if !super::super::regression_scope::is_skipped(state, api)
            && api != &state.api
            && slice.phase == RewritePhase::ImplementationRequired
            && slice.active_issue.is_some()
            && !slice.system_repair_accepted
        {
            scopes.push(RewriteWorkScope::Api { api: api.clone() });
        }
    }
    scopes.extend(
        state
            .process_outputs
            .inventory
            .iter()
            .filter(|item| {
                item.status == RewriteProcessOutputStatus::ImplementationRequired
                    && item.issue.is_some()
            })
            .map(|item| RewriteWorkScope::ProcessOutput {
                id: item.id.clone(),
            }),
    );
    scopes
}

pub(in crate::rewrite) fn scoped(
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> Result<RewriteState> {
    match scope {
        RewriteWorkScope::Api { api } => {
            let mut selected = inventory::scoped(state, Some(&api.parse()?))?;
            selected.process_outputs.current_id = None;
            Ok(selected)
        }
        RewriteWorkScope::ProcessOutput { id } => process_outputs::scoped(state, id),
    }
}

pub(in crate::rewrite) fn observation<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a RewriteWorkerObservation> {
    let observation = state
        .worker_bindings
        .get(&scope.binding_key())?
        .observation
        .as_ref()?;
    (observation.dispatch_id == super::dispatch_id(state, scope)
        && observation.recording_run_id == state.recording_run_id)
        .then_some(observation)
}

pub(in crate::rewrite) fn coverage(
    state: &RewriteState,
    scope: &RewriteWorkScope,
) -> RewriteWorkerCoverageState {
    use RewriteWorkerCoverageState as Coverage;
    let Some(binding) = state.worker_bindings.get(&scope.binding_key()) else {
        return Coverage::DispatchRequired;
    };
    if binding.confirmed_dispatch_id != super::dispatch_id(state, scope) {
        return Coverage::ResumeRequired;
    }
    let Some(observation) = observation(state, scope) else {
        return Coverage::StatusRequired;
    };
    match observation.activity {
        RewriteWorkerActivity::Idle | RewriteWorkerActivity::ReworkRequired => {
            Coverage::ResumeRequired
        }
        RewriteWorkerActivity::HandoffReady => Coverage::IntegrationRequired,
        RewriteWorkerActivity::Integrated => Coverage::VerificationRequired,
        RewriteWorkerActivity::Running | RewriteWorkerActivity::Queued => {
            let fresh = observation.coordinator_reported
                && DateTime::parse_from_rfc3339(&observation.observed_at)
                    .ok()
                    .is_some_and(|observed| {
                        let age = Utc::now().signed_duration_since(observed).num_seconds();
                        (0..RUNNING_OBSERVATION_SECONDS).contains(&age)
                    });
            if fresh {
                Coverage::Running
            } else {
                Coverage::StatusRequired
            }
        }
    }
}

#[cfg(test)]
pub(in crate::rewrite) fn record_running_for_test(
    state: &mut RewriteState,
    scope: &RewriteWorkScope,
) {
    let observation = RewriteWorkerObservation {
        dispatch_id: super::dispatch_id(state, scope),
        recording_run_id: state.recording_run_id.clone(),
        activity: RewriteWorkerActivity::Running,
        observed_at: Utc::now().to_rfc3339(),
        coordinator_reported: true,
        handoff_id: None,
        integrated_target_fingerprint: None,
    };
    state
        .worker_bindings
        .get_mut(&scope.binding_key())
        .unwrap()
        .observation = Some(observation);
}

pub(in crate::rewrite) fn acceptance_ready(state: &RewriteState, scope: &RewriteWorkScope) -> bool {
    super::super::repair::replay_ready(state, scope)
        || (super::issue_for_scope(state, scope).is_some()
            && coverage(state, scope) == RewriteWorkerCoverageState::VerificationRequired)
}

pub(in crate::rewrite) fn report_command(
    target_root: &Path,
    agent_handle: Option<&str>,
    integrated: bool,
) -> super::super::model::RewriteCommandSpec {
    let mut argv = vec!["worker".to_string(), "report".to_string()];
    let mut env = Vec::new();
    super::identity::command_handle(&mut argv, &mut env, agent_handle);
    if integrated {
        argv.extend(["--activity".to_string(), "integrated".to_string()]);
        env.push(HANDOFF_ENV.to_string());
        env.push("BACKEND_REWRITE_WORKER_REVIEW_REPORT".to_string());
    } else {
        env.push(ACTIVITY_ENV.to_string());
    }
    action::command(target_root, argv, env)
}

#[cfg(test)]
mod tests;
