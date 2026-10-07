//! Atomic API/recording transition; worker feedback is folded into persisted state.
use super::*;

pub(super) async fn advance_rewrite(options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    let route_batch = matches!(options.api, Some(RewriteApiSelector::Route(_)));
    let api = match options.api.as_ref() {
        Some(RewriteApiSelector::Motan(api)) => Some(api.clone()),
        Some(selector @ RewriteApiSelector::Route(_)) => {
            let state = RewriteStore::new(&options.target_root)?.load()?.context(
                "route selection requires a recorded API inventory; start with next without --api",
            )?;
            Some(api_selector::select(&state, selector)?)
        }
        None => None,
    };
    advance_atomic(AtomicNextOptions {
        target_root: options.target_root,
        api,
        process_output: options.process_output,
        source_route: options.source_route,
        route_batch,
    })
    .await
}

struct AtomicNextOptions {
    target_root: PathBuf,
    api: Option<RecordingApi>,
    process_output: Option<String>,
    source_route: Option<String>,
    route_batch: bool,
}

impl AtomicNextOptions {
    fn uses_route_batch(&self, state: &RewriteState) -> bool {
        self.route_batch
            || self.api.is_none()
                && self.process_output.is_none()
                && !state.api.is_empty()
                && !api_selector::work_scope(state, &state.api)
                    .binding_key()
                    .contains(' ')
    }
}

async fn advance_atomic(options: AtomicNextOptions) -> Result<RewriteActionEnvelope> {
    if let Some(envelope) = purpose::pending(&options.target_root)? {
        return Ok(envelope);
    }
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    ensure!(
        options.api.is_none() || options.process_output.is_none(),
        "--api and --process-output are mutually exclusive"
    );
    ensure!(
        options.process_output.is_none() || options.source_route.is_none(),
        "--source-route is valid only with --api"
    );
    let store = RewriteStore::new(&target_root)?;
    let requested_api = options.api.as_ref().map(ToString::to_string);
    let requested_process_output = options.process_output.clone();
    let Some(_lock) = store.try_lock()? else {
        if let Some(state) = store.load()? {
            if let Some(envelope) = execution::worker_action_while_busy(&target_root, &state) {
                return Ok(envelope);
            }
            match traffic_operation::state(&target_root)? {
                traffic_operation::TrafficOperationState::Live(active) => {
                    let mut envelope =
                        action::wait_envelope(&target_root, &state, requested_api, &active);
                    if let Some(id) = requested_process_output.as_deref() {
                        action::retarget_wait_status_for_process_output(
                            &mut envelope,
                            &target_root,
                            id,
                        );
                    }
                    return Ok(envelope);
                }
                traffic_operation::TrafficOperationState::Stale(_) => {
                    return Ok(action::recovery_required(&target_root));
                }
                traffic_operation::TrafficOperationState::Absent => {}
            }
            return Ok(match store.lock_state()? {
                RewriteLockState::Live => {
                    let mut envelope =
                        action::coordinator_wait_envelope(&target_root, &state, requested_api);
                    if let Some(id) = requested_process_output.as_deref() {
                        action::retarget_wait_status_for_process_output(
                            &mut envelope,
                            &target_root,
                            id,
                        );
                    }
                    envelope
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
                let mut envelope =
                    action::wait_envelope(&target_root, &state, requested_api, &active);
                if let Some(id) = requested_process_output.as_deref() {
                    action::retarget_wait_status_for_process_output(
                        &mut envelope,
                        &target_root,
                        id,
                    );
                }
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
            if !state.api_inventory.is_empty() {
                process_outputs::ensure_inventory_matches(&state, &project.process_outputs)?;
            }
            let target_fingerprint = fingerprint::repository_fingerprint(&target_root)?;
            let invalidated =
                inventory::defer_completed_for_target_change(&mut state, &target_fingerprint)?;
            let process_invalidated =
                process_outputs::defer_for_target_change(&mut state, &target_fingerprint);
            if recording::begin_pending_capture_refresh(&target_root, &mut state)? {
                store.save(&state)?;
            }
            let active_comparison_stale = state.phase == RewritePhase::ComparisonRecordingRequired
                && state.target_fingerprint.as_deref() != Some(target_fingerprint.as_str());
            if active_comparison_stale {
                state.phase = RewritePhase::ApiPending;
                state.e2e_current = false;
                state.comparison_current = false;
                state.comparison_run_id = None;
                state.comparison_rejection = None;
                state.active_issue = None;
                state.target_fingerprint = None;
                state.bump();
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
                && matches!(
                    state.phase,
                    RewritePhase::RecordingRequired | RewritePhase::ComparisonRecordingRequired
                )
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
                if migrated || invalidated || process_invalidated || active_comparison_stale {
                    store.save(&state)?;
                }
                return Ok(action::api_selection_wait_envelope(
                    &target_root,
                    &state,
                    requested_api.to_string(),
                ));
            }
            if let Some(id) = options.process_output.as_deref() {
                let scope = RewriteWorkScope::ProcessOutput { id: id.to_string() };
                if let Some(action) =
                    worker::scheduler::acceptance_gate(&target_root, &state, &scope)
                {
                    return Ok(action::envelope(&target_root, &state, action));
                }
                if (worker::runtime::acceptance_ready(&state, &scope)
                    || review::requires_delivery_review(&target_root, &state))
                    && let Some(review) = review::gate(&target_root, &state, &project.pr_base)?
                {
                    return Ok(action::envelope(&target_root, &state, review));
                }
                process_outputs::activate_and_compare(
                    &target_root,
                    &mut state,
                    id,
                    &target_fingerprint,
                    &project.process_outputs,
                    &project.process_output_rules,
                )?;
                store.save(&state)?;
                progress_publication::synchronize_if_complete(&target_root, &state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if options.api.is_some() {
                state.process_outputs.current_id = None;
            }
            if state.phase == RewritePhase::SliceComplete
                && options
                    .api
                    .as_ref()
                    .is_none_or(|api| api.to_string() == state.api)
            {
                if transition::complete_replay_if_ready(&target_root, &mut state)? {
                    store.save(&state)?;
                    return Ok(action::for_state(&target_root, &state));
                }
                if migrated || invalidated || process_invalidated || active_comparison_stale {
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
            if migrated
                || invalidated
                || process_invalidated
                || active_comparison_stale
                || activated
                || bound
            {
                store.save(&state)?;
            }
            state
        }
        None => {
            ensure!(
                options.process_output.is_none(),
                "--process-output requires an initialized workflow"
            );
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
            let mut state =
                initialization::new_state(&target_root, api, source_route, recording_apis)?;
            regression_scope::apply(&target_root, &mut state)?;
            if crate::config::regression::RegressionScope::load(&target_root)?
                .recording_run_id
                .is_none()
            {
                let excluded_run_id = state.recording_run_id.clone();
                recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))?;
            }
            store.save(&state)?;
            state
        }
    };

    if repair::initialize_legacy_acceptance(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if preparation::restore_legacy_background_rule_recording_request(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if preparation::restore_stale_dependency_finalize_result(&target_root, &mut state)? {
        store.save(&state)?;
    }

    if state.phase == RewritePhase::RecordingRequired
        && crate::config::regression::RegressionScope::load(&target_root)?
            .recording_run_id
            .is_none()
        && recording::standard_recording_input_source(&state).is_none()
        && !recording::requires_external_live_traffic(&state)
    {
        let excluded_run_id = state.recording_run_id.clone();
        if recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))? {
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
                regression_scope::ensure_fresh_allowed(&target_root).context(error.to_string())?;
                state.recording_rejection = Some(artifacts::recording_rejection(&error));
                state.recording_run_id =
                    artifacts::allocate_run_id(&target_root, ManagedRecordingOperation::Record)?;
                if let Some(refresh) = state.recording_refresh.as_mut() {
                    refresh.recording_run_id = Some(state.recording_run_id.clone());
                }
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            if case_patterns::identify_after_finalized_recording(&target_root, &mut state)? {
                state.recording_rejection = None;
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            let apis = match artifacts::standard_recording_apis(&target_root, &state) {
                Ok(apis) => apis,
                Err(error) => {
                    regression_scope::ensure_fresh_allowed(&target_root)
                        .context(error.to_string())?;
                    state.recording_rejection = Some(artifacts::recording_rejection(&error));
                    state.recording_run_id = artifacts::allocate_run_id(
                        &target_root,
                        ManagedRecordingOperation::Record,
                    )?;
                    if let Some(refresh) = state.recording_refresh.as_mut() {
                        refresh.recording_run_id = Some(state.recording_run_id.clone());
                    }
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
            process_outputs::install(&mut state, &project.process_outputs);
            state.recording_refresh = None;
            regression_scope::apply(&target_root, &mut state)?;
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
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            let route_batch = options.uses_route_batch(&state);
            run_and_transition(&target_root, &mut state, route_batch).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ImplementationRequired => {
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
            state.comparison_current = false;
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Replay,
            )?;
            let route_batch = options.uses_route_batch(&state);
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

            if regression_scope::start_if_required(&target_root, &mut state)? {
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
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
            run_and_transition(&target_root, &mut state, route_batch).await?;
            store.save(&state)?;
            Ok(action::for_state(&target_root, &state))
        }
        RewritePhase::ComparisonRecordingRequired => {
            let run_id = state
                .comparison_run_id
                .clone()
                .context("comparison phase has no allocated run id")?;
            match artifacts::comparison_recording_publication(&target_root, &run_id)? {
                artifacts::RecordingPublication::Missing => {
                    return Ok(action::for_state(&target_root, &state));
                }
                artifacts::RecordingPublication::Running => {
                    return action::for_status(&target_root, &state);
                }
                artifacts::RecordingPublication::Finalized => {}
            }
            if let Err(error) = artifacts::validate_comparison_recording(&target_root, &state) {
                state.comparison_rejection = Some(artifacts::comparison_rejection(&error));
                state.comparison_run_id = Some(artifacts::allocate_run_id(
                    &target_root,
                    ManagedRecordingOperation::RecordComparison,
                )?);
                state.bump();
                store.save(&state)?;
                return Ok(action::for_state(&target_root, &state));
            }
            state.comparison_rejection = None;
            if review::requires_delivery_review(&target_root, &state)
                && let Some(required) = review::gate(&target_root, &state, &project.pr_base)?
            {
                return Ok(action::envelope(&target_root, &state, required));
            }
            let _traffic = claim_traffic_operation(
                &target_root,
                &state,
                traffic_operation::TrafficOperationKind::Comparison,
            )?;
            compare_and_transition(&target_root, &mut state)?;
            store.save(&state)?;
            progress_publication::synchronize_if_complete(&target_root, &state)?;
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
                traffic_operation::TrafficOperationKind::Recording => "recording",
                traffic_operation::TrafficOperationKind::Replay => "replay",
                traffic_operation::TrafficOperationKind::Comparison => "comparison",
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
