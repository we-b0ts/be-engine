//! Validate worker callbacks and bind observations to the current dispatch.
use super::binding::dispatch_id;
use crate::fingerprint;
use crate::runtime_identity::validate_identity;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use traffic_rewrite_model::rewrite::{
    RewriteState, RewriteWorkScope, RewriteWorkerActivity, RewriteWorkerCoverageState,
    RewriteWorkerObservation,
};

const RUNNING_OBSERVATION_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone)]
pub struct RewriteWorkerReportOptions {
    pub target_root: PathBuf,
    pub agent_handle: String,
    pub activity: RewriteWorkerActivity,
    pub handoff_id: Option<String>,
    pub review_report: Option<PathBuf>,
    /// Exact worker or published integration commit; no source review required.
    pub delivery_commit: Option<String>,
}

pub fn apply_report(
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
        binding.confirmed_dispatch_id == dispatch_id(state, scope),
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
            validate_identity("worker handoff id", handoff, 512)?;
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
        dispatch_id: dispatch_id(state, scope),
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

pub fn observation<'a>(
    state: &'a RewriteState,
    scope: &RewriteWorkScope,
) -> Option<&'a RewriteWorkerObservation> {
    let observation = state
        .worker_bindings
        .get(&scope.binding_key())?
        .observation
        .as_ref()?;
    (observation.dispatch_id == dispatch_id(state, scope)
        && observation.recording_run_id == state.recording_run_id)
        .then_some(observation)
}

pub fn coverage(state: &RewriteState, scope: &RewriteWorkScope) -> RewriteWorkerCoverageState {
    use RewriteWorkerCoverageState as Coverage;
    let Some(binding) = state.worker_bindings.get(&scope.binding_key()) else {
        return Coverage::DispatchRequired;
    };
    if binding.confirmed_dispatch_id != dispatch_id(state, scope) {
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
