//! Atomic API/recording transition; worker feedback is folded into persisted state.
use super::verification::run_and_transition;
use super::*;

pub(super) struct AdvanceResult {
    pub envelope: RewriteActionEnvelope,
    /// A fresh pass, or a terminal round result with remaining members to verify.
    pub replay_can_continue: bool,
}

impl AdvanceResult {
    pub fn without_replay(envelope: RewriteActionEnvelope) -> Self {
        Self {
            envelope,
            replay_can_continue: false,
        }
    }
}

pub(super) async fn advance_rewrite(options: RewriteNextOptions) -> Result<AdvanceResult> {
    let route_batch = matches!(options.api, Some(RewriteApiSelector::Route(_)));
    let api = match options.api.as_ref() {
        Some(RewriteApiSelector::Motan(api)) => Some(api.clone()),
        Some(selector @ RewriteApiSelector::Route(_)) => {
            let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
            let mut state = RewriteStore::new(&root)?.load()?.context(
                "route selection requires a recorded API inventory; start with next without --api",
            )?;
            review::pre_revalidation::reconcile(&root, &mut state)?;
            Some(api_selector::select(&state, selector)?)
        }
        None => None,
    };
    let mut replay_can_continue = false;
    let envelope = advance_atomic(
        AtomicNextOptions {
            target_root: options.target_root,
            api,
            source_route: options.source_route,
            route_batch,
        },
        &mut replay_can_continue,
    )
    .await?;
    Ok(AdvanceResult {
        envelope,
        replay_can_continue,
    })
}

struct AtomicNextOptions {
    target_root: PathBuf,
    api: Option<RecordingApi>,
    source_route: Option<String>,
    route_batch: bool,
}

impl AtomicNextOptions {
    fn uses_route_batch(&self, state: &RewriteState) -> bool {
        self.route_batch
            || self.api.is_none()
                && !state.api.is_empty()
                && !api_selector::work_scope(state, &state.api)
                    .binding_key()
                    .contains(' ')
    }
}

async fn advance_atomic(
    options: AtomicNextOptions,
    replay_can_continue: &mut bool,
) -> Result<RewriteActionEnvelope> {
    if let Some(envelope) = purpose::pending(&options.target_root)? {
        return Ok(envelope);
    }
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let requested_api = options.api.as_ref().map(ToString::to_string);
    let Some(_lock) = store.try_lock()? else {
        if let Some(state) = store.load()? {
            if let Some(envelope) = execution::worker_action_while_busy(&target_root, &state) {
                return Ok(envelope);
            }
            match traffic_operation::state(&target_root)? {
                traffic_operation::TrafficOperationState::Live(active) => {
                    let envelope =
                        action::wait_envelope(&target_root, &state, requested_api, &active);
                    return Ok(envelope);
                }
                traffic_operation::TrafficOperationState::Stale(_) => {
                    return Ok(action::recovery_required(&target_root));
                }
                traffic_operation::TrafficOperationState::Absent => {}
            }
            return Ok(match store.lock_state()? {
                RewriteLockState::Live => {
                    action::coordinator_wait_envelope(&target_root, &state, requested_api)
                }
                RewriteLockState::Stale | RewriteLockState::Absent => {
                    action::recovery_required(&target_root)
                }
            });
        }
        return Ok(match store.lock_state()? {
            RewriteLockState::Live => {
                action::uninitialized_coordinator_wait_envelope(&target_root, requested_api)
            }
            RewriteLockState::Stale | RewriteLockState::Absent => {
                action::recovery_required(&target_root)
            }
        });
    };
    match traffic_operation::state(&target_root)? {
        traffic_operation::TrafficOperationState::Live(active) => {
            if let Some(state) = store.load()? {
                let envelope = action::wait_envelope(&target_root, &state, requested_api, &active);
                return Ok(envelope);
            }
        }
        traffic_operation::TrafficOperationState::Stale(_) => {
            return Ok(action::recovery_required(&target_root));
        }
        traffic_operation::TrafficOperationState::Absent => {}
    }
    if let Some(envelope) = configuration_commit::pending_locked(&target_root)? {
        return Ok(envelope);
    }
    let mut state = match store.load()? {
        Some(mut state) => {
            let migrated = inventory::initialize_legacy(&mut state);
            if let Some(required) =
                super::repository_analysis::required_action(&target_root, &state)?
            {
                if migrated {
                    store.save(&state)?;
                }
                return Ok(action::envelope(&target_root, &state, required));
            }
            if let Some(requested) = options.api.as_ref()
                && let Some(required @ RewriteAction::AdvanceRequired { .. }) =
                    super::group_replay::action(&target_root, &state)
                && matches!(&required, RewriteAction::AdvanceRequired { api: Some(api), .. }
                    if api != api_selector::public_api(&requested.to_string()))
            {
                return Ok(action::envelope(&target_root, &state, required));
            }
            if let Some(plan) = super::rule_plans::idle_action(&target_root, &state)? {
                return Ok(action::envelope(&target_root, &state, plan));
            }
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            let invalidated =
                inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            let invalidated =
                review::pre_revalidation::reconcile(&target_root, &mut state)? || invalidated;
            if recording::begin_pending_capture_refresh(&target_root, &mut state)? {
                store.save(&state)?;
            }
            if let Some(api) = options.api.as_ref()
                && let Some(envelope) =
                    regression_scope::skipped_envelope(&target_root, &state, &api.to_string())
            {
                store.save(&state)?;
                return Ok(envelope);
            }
            if let Some(requested_api) = options.api.as_ref()
                && requested_api.to_string() != state.api
                && matches!(state.phase, RewritePhase::RecordingRequired)
            {
                if !state.api_inventory.is_empty() {
                    ensure!(
                        state
                            .api_inventory
                            .iter()
                            .any(|item| item.api == requested_api.to_string()),
                        "recorded API inventory does not contain {requested_api:?}"
                    );
                }
                if migrated || invalidated {
                    store.save(&state)?;
                }
                return Ok(action::api_selection_wait_envelope(
                    &target_root,
                    &state,
                    requested_api.to_string(),
                ));
            }
            if let Some(required) = review::pre_revalidation::required_action(&target_root, &state)?
            {
                if migrated || invalidated {
                    store.save(&state)?;
                }
                return Ok(action::envelope(&target_root, &state, required));
            }
            if let Some(api) = options.api.as_ref()
                && let Some(envelope) =
                    revalidation::deferred_next_envelope(&target_root, &state, api)?
            {
                if migrated || invalidated {
                    store.save(&state)?;
                }
                return Ok(envelope);
            }
            if state.phase == RewritePhase::SliceComplete
                && !state.api_inventory.iter().any(|item| {
                    item.api == state.api
                        && item.status == model::RewriteApiStatus::RevalidationPending
                })
                && options
                    .api
                    .as_ref()
                    .is_none_or(|api| api.to_string() == state.api)
            {
                if transition::complete_replay_if_ready(&target_root, &mut state)? {
                    store.save(&state)?;
                    return Ok(action::for_state(&target_root, &state));
                }
                if migrated || invalidated {
                    store.save(&state)?;
                }
                if let Some(review) = review::required_action(&target_root, &state)? {
                    return Ok(action::envelope(&target_root, &state, review));
                }
                progress_publication::synchronize_if_complete(&target_root, &state)?;
                let scoped = inventory::scoped(&state, options.api.as_ref())?;
                return action::for_status(&target_root, &scoped);
            }
            let activated = inventory::activate_requested(&mut state, options.api.as_ref())?;
            let bound = inventory::bind_options(
                &mut state,
                options.api.as_ref(),
                options.source_route.as_deref(),
            )?;
            if migrated || invalidated || activated || bound {
                store.save(&state)?;
            }
            state
        }
        None => {
            let (api, source_route, recording_apis) = match options.api.as_ref() {
                Some(api) => {
                    let source_route = match options.source_route.as_ref() {
                        Some(route) => route.clone(),
                        None if !api.is_dynamic() => api.path_pattern().to_string(),
                        None => return Ok(action::source_route_required(&target_root, api)),
                    };
                    inventory::validate_source_route(api, &source_route)?;
                    (api.to_string(), source_route, vec![api.to_string()])
                }
                None => {
                    ensure!(
                        options.source_route.is_none(),
                        "--source-route requires --api when starting a workflow"
                    );
                    (String::new(), String::new(), Vec::new())
                }
            };
            if !source_route.is_empty() {
                validate_single_line("source route", &source_route)?;
            }
            let mut state = initialization::new_state(api, source_route, recording_apis);
            let excluded_run_id = state.recording_run_id.clone();
            recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))?;
            store.save(&state)?;
            state
        }
    };

    if repair::initialize_legacy_acceptance(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if state.phase == RewritePhase::RecordingRequired {
        let excluded_run_id = state
            .recording_input_case_source
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|id| id.to_string_lossy().into_owned())
            .or_else(|| {
                state
                    .recording_rejection
                    .as_ref()
                    .map(|_| state.recording_run_id.clone())
            });
        if recording_input::bind(&target_root, &mut state, excluded_run_id.as_deref())? {
            state.bump();
            store.save(&state)?;
        }
    }

    if transition::complete_replay_if_ready(&target_root, &mut state)? {
        store.save(&state)?;
        return Ok(action::for_state(&target_root, &state));
    }
    if let Some(envelope) = configuration_commit::pending_locked(&target_root)? {
        return Ok(envelope);
    }
    match state.phase {
        RewritePhase::RecordingRequired => {
            match artifacts::standard_recording_publication(&target_root, &state.recording_run_id)?
            {
                artifacts::RecordingPublication::Missing => {
                    return Ok(action::for_state(&target_root, &state));
                }
                artifacts::RecordingPublication::Running => {
                    return action::for_status(&target_root, &state);
                }
                artifacts::RecordingPublication::Finalized => {}
            }
            if let Err(error) = artifacts::validate_standard_recording(&target_root, &state) {
                state.recording_rejection = Some(artifacts::recording_rejection(&error));
                state.recording_after_run_id = Some(state.recording_run_id.clone());
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if case_patterns::identify_after_finalized_recording(&target_root, &mut state)? {
                state.recording_rejection = None;
                state.bump();
                store.save(&state)?;
                return action::for_status(&target_root, &state);
            }
            let apis = match artifacts::standard_recording_apis(&target_root, &state) {
                Ok(apis) => apis,
                Err(error) => {
                    state.recording_rejection = Some(artifacts::recording_rejection(&error));
                    state.recording_after_run_id = Some(state.recording_run_id.clone());
                    state.bump();
                    store.save(&state)?;
                    return Ok(action::for_state(&target_root, &state));
                }
            };
            state.recording_rejection = None;
            let recorded_cases =
                artifacts::standard_recording_api_case_counts(&target_root, &state, &apis)?;
            crate::verification_progress::begin_epoch(&target_root, &state.recording_run_id)?;
            crate::verification_progress::record_completed_batch(
                &target_root.join(".traffic-e2e/progress.yaml"),
                &state.recording_run_id,
                chrono::Utc::now().to_rfc3339(),
                recorded_cases,
            )?;
            let uses_recorded_patterns = inventory::install(&mut state, apis)?;
            state.recording_refresh = None;
            regression_scope::apply(&target_root, &mut state)?;
            super::repository_analysis::refresh(&target_root, &mut state)?;
            super::implementer::refresh(&mut state)?;
            if let Some(required) =
                super::repository_analysis::required_action(&target_root, &state)?
            {
                store.save(&state)?;
                return Ok(action::envelope(&target_root, &state, required));
            }
            if state.current_api_index.is_none() {
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if uses_recorded_patterns {
                state.phase = RewritePhase::ApiPending;
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if inventory::current_requires_source_route(&state) {
                state.phase = RewritePhase::ApiPending;
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if review::requires_delivery_review(&target_root, &state)
                && let Some(required) = review::gate(&target_root, &state, &project.pr_base)?
            {
                // Recording validation and inventory installation remain available
                // while the delivery owner refreshes the new batch's receipt.
                store.save(&state)?;
                return Ok(action::envelope(&target_root, &state, required));
            }
            preparation::prepare_recording(&target_root, &mut state)?;
            store.save(&state)?;
            if let Some(envelope) = configuration_commit::pending_locked(&target_root)? {
                return Ok(envelope);
            }
            let Some(_traffic) = claim_replay_after_plans(&target_root, &mut state)? else {
                return Ok(action::for_state(&target_root, &state));
            };
            let route_batch = options.uses_route_batch(&state);
            *replay_can_continue =
                run_and_transition(&target_root, &mut state, route_batch).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ImplementationRequired => {
            if super::replay_admission::applying_policy(&state)
                || super::replay_admission::pending_transaction(&state.active_slice)
            {
                return Ok(action::for_state(&target_root, &state));
            }
            let scope = RewriteWorkScope::Api {
                api: state.api.clone(),
            };
            if let Some(action) = worker::scheduler::acceptance_gate(&target_root, &state, &scope) {
                return Ok(action::envelope(&target_root, &state, action));
            }
            if let Some(review) = review::gate(&target_root, &state, &project.pr_base)? {
                return Ok(action::envelope(&target_root, &state, review));
            }
            // Completed APIs reopened for quality work may retain only an inventory
            // entry. Reuse the existing recording to restore preparation for Replay.
            if state
                .active_issue
                .as_ref()
                .is_some_and(|issue| issue.kind == RewriteIssueKind::TargetQuality)
                && (state.case_source.is_none() || state.group_id.is_none())
            {
                preparation::prepare_recording(&target_root, &mut state)?;
                store.save(&state)?;
                if let Some(envelope) = configuration_commit::pending_locked(&target_root)? {
                    return Ok(envelope);
                }
            }
            state.e2e_current = false;
            let Some(_traffic) = claim_replay_after_plans(&target_root, &mut state)? else {
                return Ok(action::for_state(&target_root, &state));
            };
            let route_batch = options.uses_route_batch(&state);
            *replay_can_continue =
                run_and_transition(&target_root, &mut state, route_batch).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ApiPending => {
            if review::requires_delivery_review(&target_root, &state)
                && let Some(required) = review::gate(&target_root, &state, &project.pr_base)?
            {
                return Ok(action::envelope(&target_root, &state, required));
            }

            if inventory::current_requires_source_route(&state) {
                return Ok(action::for_state(&target_root, &state));
            }
            preparation::prepare_recording(&target_root, &mut state)?;
            store.save(&state)?;
            if let Some(envelope) = configuration_commit::pending_locked(&target_root)? {
                return Ok(envelope);
            }
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            let route_batch = options.uses_route_batch(&state);
            *replay_can_continue =
                run_and_transition(&target_root, &mut state, route_batch).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::AwaitingRecordingRefresh
        | RewritePhase::SystemRepairRequired
        | RewritePhase::SliceComplete => {
            progress_publication::synchronize_if_complete(&target_root, &state)?;
            Ok(action::for_state(&target_root, &state))
        }
    }
}

fn claim_replay_after_plans(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<Option<traffic_operation::TrafficOperationGuard>> {
    // Linearize plan publication against the next Replay reservation. Expensive
    // plan validation stays outside this short lock.
    let _plans = super::rule_plans::events::lock(target_root)?;
    super::rule_plans::events::overlay(target_root, state)?;
    if super::rule_plans::pending(state) {
        return Ok(None);
    }
    claim_traffic_operation(
        target_root,
        state,
        traffic_operation::TrafficOperationKind::Replay,
    )
    .map(Some)
}

fn claim_traffic_operation(
    target_root: &Path,
    state: &RewriteState,
    kind: traffic_operation::TrafficOperationKind,
) -> Result<traffic_operation::TrafficOperationGuard> {
    let operation_id = format!(
        "traffic-{}",
        fingerprint::id(&[
            &state.workflow_id,
            &state.api,
            match kind {
                traffic_operation::TrafficOperationKind::Replay => "replay",
            },
            &state.revision.to_string(),
        ])
        .trim_start_matches("fnv1a64:")
    );
    match traffic_operation::claim_current(
        target_root,
        operation_id,
        kind,
        (!state.api.is_empty()).then(|| state.api.clone()),
    )? {
        traffic_operation::TrafficOperationClaim::Acquired(guard) => Ok(guard),
        traffic_operation::TrafficOperationClaim::Busy(active) => anyhow::bail!(
            "traffic runtime is owned by {:?} operation {}; inspect `backend-rewrite status`",
            active.kind,
            active.operation_id
        ),
        traffic_operation::TrafficOperationClaim::Stale(active) => anyhow::bail!(
            "traffic runtime has stale {:?} operation {}; execute `backend-rewrite recover`",
            active.kind,
            active.operation_id
        ),
    }
}
