use std::fs::{self, OpenOptions};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use super::action;
use super::artifacts;
use super::inventory;
use super::model::{
    RewriteActionEnvelope, RewritePhase, RewriteRecordingExecutionReport, RewriteRecordingKind,
    RewriteRecordingReason, RewriteRecordingSettings, RewriteRecordingStartReport,
    RewriteRecordingStartState, RewriteState,
};
use super::recording_action;
use super::recording_execution::{self, RecordingExecutionMarker, RecordingExecutionState};
use super::store::{RewriteLockState, RewriteStore};
use super::traffic_operation::{
    self, TrafficOperationClaim, TrafficOperationKind, TrafficOperationMarker,
    TrafficOperationState,
};
use crate::{ManagedRecordingOperation, ManagedRecordingOptions, RecordingApi};

pub(super) const STATUS_POLL_AFTER_SECONDS: u64 = 30;

#[derive(Debug, Clone)]
pub struct RewriteRecordingRequestOptions {
    pub target_root: PathBuf,
    pub kind: RewriteRecordingKind,
    pub reason: RewriteRecordingReason,
    pub duration_seconds: NonZeroU64,
    pub per_api_case_limit: NonZeroUsize,
    pub api: Option<RecordingApi>,
    pub replace_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingRecordingDisposition {
    ReturnStatus,
    ReturnAction,
    Replace,
}

pub fn request_rewrite_recording(
    options: RewriteRecordingRequestOptions,
) -> Result<RewriteActionEnvelope> {
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    super::regression_scope::ensure_fresh_allowed(&target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let requested_api = options.api.as_ref().map(ToString::to_string);
    let Some(_lock) = store.try_lock()? else {
        let state = store
            .load()?
            .context("rewrite workflow has not been initialized")?;
        return Ok(match traffic_operation::state(&target_root)? {
            TrafficOperationState::Live(active) => {
                action::wait_envelope(&target_root, &state, requested_api, &active)
            }
            TrafficOperationState::Stale(_) => action::recovery_required(&target_root),
            TrafficOperationState::Absent => match store.lock_state()? {
                RewriteLockState::Live => {
                    action::coordinator_wait_envelope(&target_root, &state, requested_api)
                }
                RewriteLockState::Stale | RewriteLockState::Absent => {
                    action::recovery_required(&target_root)
                }
            },
        });
    };
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    if inventory::initialize_legacy(&mut state) {
        store.save(&state)?;
    }
    ensure!(
        options.kind == RewriteRecordingKind::Standard,
        "only fresh standard recording requests are supported"
    );
    ensure!(
        state.phase != RewritePhase::SystemRepairRequired,
        "system repair must pass its coordinator-issued acceptance before requesting new traffic"
    );
    ensure!(
        state.recording_refresh.is_none(),
        "a recorder-capture refresh is coordinator-owned; execute the action returned by `backend-rewrite status`"
    );
    ensure!(
        state.case_pattern_identification.is_none(),
        "case path pattern identification is pending; execute action.commands.apply before requesting another recording"
    );
    let settings = RewriteRecordingSettings {
        duration_seconds: options.duration_seconds,
        per_api_case_limit: options.per_api_case_limit,
    };
    let requested_apis = requested_recording_apis(options.api.as_ref());
    if state.phase == RewritePhase::RecordingRequired {
        let publication =
            artifacts::standard_recording_publication(&target_root, &state.recording_run_id)?;
        match existing_recording_disposition(
            publication,
            &state,
            options.reason,
            settings,
            &requested_apis,
            options.replace_pending,
        )? {
            ExistingRecordingDisposition::ReturnStatus => {
                return action::for_status(&target_root, &state);
            }
            ExistingRecordingDisposition::ReturnAction => {
                return Ok(action::for_state(&target_root, &state));
            }
            ExistingRecordingDisposition::Replace => {}
        }
    }
    let run_id = artifacts::allocate_run_id_excluding(
        &target_root,
        ManagedRecordingOperation::Record,
        &[&state.recording_run_id],
    )?;
    reset_for_fresh_recording(&mut state, run_id, settings, options.reason);
    if state.recording_apis != requested_apis {
        state.recording_apis = requested_apis;
        state.recording_input_case_source = None;
        state.recording_input_diagnosis = None;
        inventory::reset_for_recording(&mut state);
    }
    if standard_recording_input_source(&state).is_none() && !requires_external_live_traffic(&state)
    {
        let excluded_run_id = state.recording_run_id.clone();
        super::recording_input::bind(&target_root, &mut state, Some(&excluded_run_id))?;
    }
    store.save(&state)?;
    Ok(action::for_state(&target_root, &state))
}

fn requested_recording_apis(api: Option<&RecordingApi>) -> Vec<String> {
    api.map(|api| vec![api.to_string()]).unwrap_or_default()
}

fn existing_recording_disposition(
    publication: artifacts::RecordingPublication,
    state: &RewriteState,
    reason: RewriteRecordingReason,
    settings: RewriteRecordingSettings,
    requested_apis: &[String],
    replace_pending: bool,
) -> Result<ExistingRecordingDisposition> {
    if publication == artifacts::RecordingPublication::Running {
        return Ok(ExistingRecordingDisposition::ReturnStatus);
    }
    let reusable =
        reuse_pending_recording(state, reason, settings, requested_apis, replace_pending)?;
    Ok(match (publication, reusable) {
        (artifacts::RecordingPublication::Finalized, true) => {
            ExistingRecordingDisposition::ReturnStatus
        }
        (artifacts::RecordingPublication::Missing, true) => {
            ExistingRecordingDisposition::ReturnAction
        }
        (_, false) => ExistingRecordingDisposition::Replace,
        (artifacts::RecordingPublication::Running, _) => unreachable!("handled above"),
    })
}

fn reuse_pending_recording(
    state: &RewriteState,
    reason: RewriteRecordingReason,
    settings: RewriteRecordingSettings,
    requested_apis: &[String],
    replace_pending: bool,
) -> Result<bool> {
    if state.recording_request_reason == Some(reason)
        && state.recording_settings == settings
        && inventory::recording_scope(state) == requested_apis
    {
        return Ok(true);
    }
    ensure!(
        replace_pending,
        "a different standard recording is already pending; inspect `backend-rewrite status` or retry with --replace-pending"
    );
    Ok(false)
}

pub fn start_rewrite_recording(
    target_root: PathBuf,
    requested_action_id: &str,
) -> Result<RewriteRecordingStartReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let lock = store.try_lock()?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let (comparison, operation, run_id, _) = recording_action_context(&target_root, &state)?;
    let expected_action_id = recording_action::recording_action_id(&state, comparison);
    ensure!(
        requested_action_id == expected_action_id,
        "recording action is stale or belongs to another workflow revision"
    );
    let Some(lock) = lock else {
        if store.lock_state()? == RewriteLockState::Stale {
            anyhow::bail!(
                "the rewrite coordinator has a stale owner; execute `backend-rewrite recover`"
            );
        }
        let active = match traffic_operation::state(&target_root)? {
            TrafficOperationState::Live(active) => Some(active),
            TrafficOperationState::Stale(_) => {
                anyhow::bail!(
                    "the traffic runtime has a stale owner; execute `backend-rewrite recover`"
                );
            }
            TrafficOperationState::Absent => None,
        };
        return Ok(waiting_start_report(
            &target_root,
            requested_action_id,
            operation,
            run_id,
            &state.api,
            active,
        ));
    };
    match traffic_operation::state(&target_root)? {
        TrafficOperationState::Live(active) if active.operation_id != requested_action_id => {
            return Ok(waiting_start_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                &state.api,
                Some(active),
            ));
        }
        TrafficOperationState::Stale(_) => {
            anyhow::bail!(
                "the traffic runtime has a stale owner; execute `backend-rewrite recover`"
            );
        }
        TrafficOperationState::Live(_) | TrafficOperationState::Absent => {}
    }
    match recording_execution::state(&target_root)? {
        RecordingExecutionState::Live(marker) => {
            ensure!(
                marker.action_id == requested_action_id,
                "another recording action is already running"
            );
            return Ok(start_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                RewriteRecordingStartState::AlreadyRunning,
            ));
        }
        RecordingExecutionState::Stale(_) => {
            anyhow::bail!(
                "the previous recording executor stopped before publishing completion; execute `backend-rewrite recover`"
            );
        }
        RecordingExecutionState::Absent => {}
    }
    let publication = recording_publication(&target_root, &state, comparison)?;
    match publication {
        artifacts::RecordingPublication::Finalized => {
            return Ok(start_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                RewriteRecordingStartState::AlreadyCompleted,
            ));
        }
        artifacts::RecordingPublication::Running => {
            anyhow::bail!(
                "the recording manifest is incomplete and has no live executor; execute `backend-rewrite recover`"
            );
        }
        artifacts::RecordingPublication::Missing => {}
    }
    let log_path = recording_execution::log_path(&target_root, &run_id);
    let log_root = log_path.parent().context("recording log has no parent")?;
    fs::create_dir_all(log_root)
        .with_context(|| format!("failed to create recording log root {}", log_root.display()))?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
        .with_context(|| format!("failed to open recording log {}", log_path.display()))?;
    let stderr = stdout.try_clone()?;
    let executable = crate::engine_binary::executable()?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("internal")
        .arg("rewrite-recording-worker")
        .arg("--target-root")
        .arg(&target_root)
        .arg(requested_action_id)
        .current_dir(&target_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command
        .spawn()
        .context("failed to start detached recording executor")?;
    let marker = RecordingExecutionMarker {
        action_id: requested_action_id.to_string(),
        run_id: run_id.clone(),
        operation: operation.script_name().to_string(),
        pid: child.id(),
    };
    if let Err(error) = recording_execution::publish(&target_root, &marker) {
        let _ = child.kill();
        return Err(error);
    }
    let traffic_marker = TrafficOperationMarker {
        operation_id: requested_action_id.to_string(),
        kind: if comparison {
            TrafficOperationKind::Comparison
        } else {
            TrafficOperationKind::Recording
        },
        api: comparison.then(|| state.api.clone()),
        started_at: chrono::Utc::now().to_rfc3339(),
        pid: child.id(),
    };
    match traffic_operation::claim(&target_root, traffic_marker)? {
        TrafficOperationClaim::Acquired(guard) => guard.disarm(),
        TrafficOperationClaim::Busy(active) => {
            let _ = child.kill();
            recording_execution::clear(&target_root, requested_action_id)?;
            return Ok(waiting_start_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                &state.api,
                Some(active),
            ));
        }
        TrafficOperationClaim::Stale(_) => {
            let _ = child.kill();
            recording_execution::clear(&target_root, requested_action_id)?;
            anyhow::bail!(
                "the traffic runtime has a stale owner; execute `backend-rewrite recover`"
            );
        }
    }
    drop(lock);
    Ok(start_report(
        &target_root,
        requested_action_id,
        operation,
        run_id,
        RewriteRecordingStartState::Started,
    ))
}

pub async fn execute_rewrite_recording_worker(
    target_root: PathBuf,
    requested_action_id: &str,
) -> Result<RewriteRecordingExecutionReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let lock = loop {
        if let Some(lock) = store.try_lock()? {
            break lock;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "detached recording executor could not acquire the coordinator lock"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let result =
        execute_rewrite_recording_locked(target_root.clone(), requested_action_id, store, lock)
            .await;
    match result {
        Ok(report) => {
            traffic_operation::clear_owned(&target_root, requested_action_id)?;
            recording_execution::clear(&target_root, requested_action_id)?;
            Ok(report)
        }
        Err(runtime_error) => {
            let store = RewriteStore::new(&target_root)?;
            let state = store
                .load()?
                .context("rewrite workflow has not been initialized")?;
            let (comparison, operation, run_id, manifest) =
                recording_action_context(&target_root, &state)?;
            if recording_publication(&target_root, &state, comparison)?
                != artifacts::RecordingPublication::Finalized
            {
                return Err(runtime_error);
            }
            if comparison {
                artifacts::validate_comparison_recording(&target_root, &state)?;
            } else {
                artifacts::validate_standard_recording(&target_root, &state)?;
            }
            recording_execution::clear(&target_root, requested_action_id)?;
            traffic_operation::clear_owned(&target_root, requested_action_id)?;
            Ok(execution_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                manifest,
                false,
            ))
        }
    }
}

async fn execute_rewrite_recording_locked(
    target_root: PathBuf,
    requested_action_id: &str,
    store: RewriteStore,
    _lock: super::store::RewriteLock,
) -> Result<RewriteRecordingExecutionReport> {
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let (comparison, operation, run_id, manifest) = recording_action_context(&target_root, &state)?;
    let expected_action_id = recording_action::recording_action_id(&state, comparison);
    ensure!(
        requested_action_id == expected_action_id,
        "recording action is stale or belongs to another workflow revision"
    );
    match recording_publication(&target_root, &state, comparison)? {
        artifacts::RecordingPublication::Finalized => {
            if comparison {
                artifacts::validate_comparison_recording(&target_root, &state)?;
            } else {
                artifacts::validate_standard_recording(&target_root, &state)?;
            }
            return Ok(execution_report(
                &target_root,
                requested_action_id,
                operation,
                run_id,
                manifest,
                true,
            ));
        }
        artifacts::RecordingPublication::Running => {
            anyhow::bail!("the recording manifest is incomplete; execute `backend-rewrite recover`")
        }
        artifacts::RecordingPublication::Missing => {}
    }
    let request_source = if comparison {
        Some(
            state
                .case_source
                .clone()
                .context("comparison recording has no finalized standard case source")?,
        )
    } else {
        standard_recording_input_source(&state).map(Path::to_path_buf)
    };
    let apis = if comparison {
        vec![state.api.parse::<RecordingApi>()?]
    } else {
        inventory::recording_scope(&state)
            .iter()
            .map(|api| api.parse::<RecordingApi>())
            .collect::<Result<Vec<_>>>()?
    };
    let result = crate::run_managed_recording(ManagedRecordingOptions {
        target_root: target_root.clone(),
        operation,
        run_id: Some(run_id.clone()),
        duration_seconds: state.recording_settings.duration_seconds,
        // The project configuration and verification policy own source-after.
        // The rewrite coordinator must not turn an optional diagnostic into
        // an unconditional second source request.
        baseline_recheck: false,
        apis,
        per_api_case_limit: Some(state.recording_settings.per_api_case_limit),
        request_source,
    })
    .await?;
    Ok(execution_report(
        &target_root,
        requested_action_id,
        operation,
        run_id,
        result.manifest,
        false,
    ))
}

fn recording_action_context(
    target_root: &std::path::Path,
    state: &RewriteState,
) -> Result<(bool, ManagedRecordingOperation, String, PathBuf)> {
    match state.phase {
        RewritePhase::RecordingRequired => Ok((
            false,
            ManagedRecordingOperation::Record,
            state.recording_run_id.clone(),
            artifacts::recording_manifest(target_root, &state.recording_run_id),
        )),
        RewritePhase::ComparisonRecordingRequired => {
            ensure!(
                state.require_comparison,
                "regression.yaml does not require comparison; execute `backend-rewrite next`"
            );
            let run_id = state
                .comparison_run_id
                .clone()
                .context("comparison recording action has no run id")?;
            Ok((
                true,
                ManagedRecordingOperation::RecordComparison,
                run_id.clone(),
                artifacts::comparison_manifest(target_root, &run_id),
            ))
        }
        _ => anyhow::bail!("rewrite workflow has no recording action to execute"),
    }
}

fn recording_publication(
    target_root: &std::path::Path,
    state: &RewriteState,
    comparison: bool,
) -> Result<artifacts::RecordingPublication> {
    if comparison {
        let run_id = state
            .comparison_run_id
            .as_deref()
            .context("comparison recording action has no run id")?;
        artifacts::comparison_recording_publication(target_root, run_id)
    } else {
        artifacts::standard_recording_publication(target_root, &state.recording_run_id)
    }
}

fn start_report(
    target_root: &std::path::Path,
    action_id: &str,
    operation: ManagedRecordingOperation,
    run_id: String,
    execution_state: RewriteRecordingStartState,
) -> RewriteRecordingStartReport {
    RewriteRecordingStartReport {
        action_id: action_id.to_string(),
        run_id,
        operation: operation.script_name().to_string(),
        execution_state,
        status_poll_after_seconds: (execution_state
            != RewriteRecordingStartState::AlreadyCompleted)
            .then_some(STATUS_POLL_AFTER_SECONDS),
        waiting_on: None,
        status: action::status_command(target_root),
    }
}

fn waiting_start_report(
    target_root: &std::path::Path,
    action_id: &str,
    operation: ManagedRecordingOperation,
    run_id: String,
    api: &str,
    active: Option<TrafficOperationMarker>,
) -> RewriteRecordingStartReport {
    RewriteRecordingStartReport {
        action_id: action_id.to_string(),
        run_id,
        operation: operation.script_name().to_string(),
        execution_state: RewriteRecordingStartState::WaitingForTrafficRuntime,
        status_poll_after_seconds: Some(STATUS_POLL_AFTER_SECONDS),
        waiting_on: active.as_ref().map(traffic_operation::view),
        status: action::status_command_for_api(target_root, (!api.is_empty()).then_some(api)),
    }
}

fn execution_report(
    target_root: &std::path::Path,
    action_id: &str,
    operation: ManagedRecordingOperation,
    run_id: String,
    manifest: PathBuf,
    already_completed: bool,
) -> RewriteRecordingExecutionReport {
    RewriteRecordingExecutionReport {
        action_id: action_id.to_string(),
        run_id,
        operation: match operation {
            ManagedRecordingOperation::Record => "record".to_string(),
            ManagedRecordingOperation::RecordComparison => "record_comparison".to_string(),
        },
        already_completed,
        manifest,
        next: action::next_command(target_root),
    }
}

pub(super) fn reset_for_fresh_recording(
    state: &mut RewriteState,
    run_id: String,
    settings: RewriteRecordingSettings,
    reason: RewriteRecordingReason,
) {
    // Every replacement run also owns any outstanding capture refresh. Keep
    // its applied rules and baseline reference until publication validates.
    if let Some(refresh) = state.recording_refresh.as_mut() {
        refresh.recording_run_id = Some(run_id.clone());
    }
    state.recording_input_case_source = if reason.requires_external_live_traffic() {
        None
    } else {
        state
            .case_source
            .clone()
            .or_else(|| state.recording_input_case_source.clone())
    };
    state.recording_input_diagnosis = None;
    state.phase = RewritePhase::RecordingRequired;
    inventory::reset_for_recording(state);
    if reason == RewriteRecordingReason::SourceBaselineChanged {
        state.source_route_bindings.clear();
    }
    state.recording_run_id = run_id;
    state.recording_rejection = None;
    state.recording_settings = settings;
    state.recording_request_reason = Some(reason);
    state.comparison_run_id = None;
    state.comparison_rejection = None;
    state.case_source = None;
    state.case_inventory_id = None;
    state.source_revision = None;
    state.group_id = None;
    state.target_fingerprint = None;
    state.attempts.clear();
    state.attempt_delta = None;
    state.active_issue = None;
    state.rule_plan = None;
    state.dependency_rule_plan = None;
    state.recorder_capture_plan = None;
    state.route = None;
    state.e2e_current = false;
    state.comparison_current = false;
    state.bump();
}

pub(super) fn begin_pending_capture_refresh(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    let Some(refresh) = state.recording_refresh.as_ref() else {
        return Ok(false);
    };
    if refresh.recording_run_id.is_some() {
        return Ok(false);
    }
    if state.phase == RewritePhase::RecordingRequired
        && matches!(
            state.recording_request_reason,
            Some(
                RewriteRecordingReason::RecorderContractChanged
                    | RewriteRecordingReason::SourceBaselineChanged
            )
        )
        && state.case_source.is_none()
        && state.recording_input_case_source.is_none()
    {
        // Older repair verification reset the baseline but left this refresh
        // unbound. The repair already reserved a fresh run using the current
        // recorder contract. Adopt it before the pre-scheduling revision guard;
        // next must still validate its publication, scope and recorded cases.
        state
            .recording_refresh
            .as_mut()
            .expect("refresh was checked")
            .recording_run_id = Some(state.recording_run_id.clone());
        state.bump();
        return Ok(true);
    }
    if inventory::has_runnable_work(state) {
        return Ok(false);
    }
    super::regression_scope::ensure_fresh_allowed(target_root)?;
    ensure!(
        super::fingerprint::project_config_revision(target_root)?
            == refresh.project_config_revision,
        "project config changed after scheduling the recording refresh; re-plan the affected rule"
    );
    ensure!(
        super::fingerprint::source_traffic_policy_revision(target_root)?
            == refresh.source_traffic_policy_revision,
        "source traffic policy changed after scheduling the recording refresh; re-plan the affected rule"
    );
    let run_id = artifacts::allocate_run_id_excluding(
        target_root,
        ManagedRecordingOperation::Record,
        &[&state.recording_run_id],
    )?;
    reset_for_fresh_recording(
        state,
        run_id,
        state.recording_settings,
        RewriteRecordingReason::RecorderContractChanged,
    );
    Ok(true)
}

pub(super) fn requires_external_live_traffic(state: &RewriteState) -> bool {
    state
        .recording_request_reason
        .is_some_and(RewriteRecordingReason::requires_external_live_traffic)
}

pub(super) fn standard_recording_input_source(state: &RewriteState) -> Option<&Path> {
    (!requires_external_live_traffic(state))
        .then_some(state.recording_input_case_source.as_deref())
        .flatten()
}

#[cfg(test)]
mod tests;
