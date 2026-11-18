//! Detached execution of coordinator-owned verification steps. Worker feedback
//! remains available while the existing serialized transition holds its lock.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::model::{RewriteAction, RewriteActionEnvelope, RewriteExecutionMode, RewriteState};
use super::store::{RewriteLockState, RewriteStore};
use super::{RewriteContext, RewriteNextOptions, RewriteTargetQualityOptions, action};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Request {
    Next {
        api: Option<String>,
        source_route: Option<String>,
        #[serde(default)]
        execution_mode: RewriteExecutionMode,
    },
    TargetQuality {
        api: String,
        gate_id: String,
        hardcode_ai_verified: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Execution {
    id: String,
    pid: u32,
    request: Request,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recording_run_id: Option<String>,
    finished: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn start_next(mut options: RewriteNextOptions) -> Result<RewriteActionEnvelope> {
    if let Some(envelope) = super::purpose::pending(&options.target_root)? {
        return Ok(envelope);
    }
    let target_root = fs::canonicalize(&options.target_root)?;
    let execution_mode = super::next::mode(&options)?;
    let current = if let Some(api) = options.api.as_ref() {
        super::status_rewrite_for_selector(
            RewriteContext {
                target_root: target_root.clone(),
            },
            api,
        )?
    } else {
        super::status_rewrite(RewriteContext {
            target_root: target_root.clone(),
        })?
    };
    // Runtime actions are returned to the state-machine coordinator, not executed
    // by a CLI that has no authority to manufacture task handles or handoffs.
    if current.initialized
        && options.source_route.is_none()
        && !matches!(current.action, RewriteAction::AdvanceRequired { .. })
    {
        return Ok(from_status(current));
    }
    // Freeze the selected scope before launching the detached operation. Its
    // own execution marker must not turn a later global selection into waiting.
    if options.api.is_none() {
        options.api = super::next::selected_api(&current.action)?;
    }
    start(
        &target_root,
        Request::Next {
            api: options.api.map(|api| api.to_string()),
            source_route: options.source_route,
            execution_mode,
        },
    )
}

pub fn start_quality(options: RewriteTargetQualityOptions) -> Result<RewriteActionEnvelope> {
    super::target_quality::run(options)
}

fn start(target_root: &Path, request: Request) -> Result<RewriteActionEnvelope> {
    let store = RewriteStore::new(target_root)?;
    let Some(lock) = store.try_lock()? else {
        return super::worker::runtime::current_envelope(target_root);
    };
    if busy(target_root)?
        || !matches!(
            super::traffic_operation::state(target_root)?,
            super::traffic_operation::TrafficOperationState::Absent
        )
    {
        drop(lock);
        return super::worker::runtime::current_envelope(target_root);
    }
    let recording_run_id = store
        .load()?
        .map(|state| state.recording_run_id)
        .filter(|id| !id.is_empty());
    let id = format!("operation-{}", uuid::Uuid::new_v4().simple());
    let directory = root(target_root);
    fs::create_dir_all(&directory)?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(directory.join(format!("{id}.log")))?;
    let mut command = std::process::Command::new(crate::engine_binary::executable()?);
    command
        .args(["internal", "rewrite-operation-worker", "--target-root"])
        .arg(target_root)
        .arg(&id)
        .current_dir(target_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
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
        .context("failed to start the coordinator operation")?;
    let execution = Execution {
        id,
        pid: child.id(),
        request,
        recording_run_id,
        finished: false,
        error: None,
    };
    if let Err(error) = save(target_root, &execution) {
        let _ = child.kill();
        return Err(error);
    }
    drop(lock);
    super::worker::runtime::current_envelope(target_root)
}

pub async fn execute(target_root: PathBuf, id: &str) -> Result<RewriteActionEnvelope> {
    let target_root = fs::canonicalize(target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let execution = loop {
        if let Some(execution) = load(&target_root)?
            && execution.id == id
            && execution.pid == std::process::id()
            && store.lock_state()? == RewriteLockState::Absent
        {
            break execution;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "coordinator operation did not receive its launch handoff"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    ensure!(
        !execution.finished,
        "coordinator operation already completed"
    );
    let result = match &execution.request {
        Request::Next {
            api,
            source_route,
            execution_mode,
        } => {
            super::next::run_selected(
                RewriteNextOptions {
                    target_root: target_root.clone(),
                    api: api.as_deref().map(str::parse).transpose()?,
                    source_route: source_route.clone(),
                },
                *execution_mode,
            )
            .await
        }
        Request::TargetQuality {
            api,
            gate_id,
            hardcode_ai_verified,
        } => super::target_quality::run(RewriteTargetQualityOptions {
            target_root: target_root.clone(),
            api: api.parse()?,
            gate_id: gate_id.clone(),
            hardcode_ai_verified: hardcode_ai_verified.clone(),
        }),
    };
    let _lock = store.lock()?;
    let mut current = load(&target_root)?.context("coordinator operation marker disappeared")?;
    ensure!(
        current.id == id && current.pid == std::process::id(),
        "coordinator operation ownership changed"
    );
    current.finished = true;
    current.error = result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}").chars().take(1024).collect());
    save(&target_root, &current)?;
    result
}

/// Retain the current selected step for explicit retry after an auto-next failure.
pub(super) fn update_next_scope(options: &RewriteNextOptions) -> Result<()> {
    let Some(mut execution) = load(&options.target_root)? else {
        return Ok(());
    };
    if execution.pid != std::process::id() || execution.finished {
        return Ok(());
    }
    if let Request::Next {
        api, source_route, ..
    } = &mut execution.request
    {
        *api = options.api.as_ref().map(ToString::to_string);
        *source_route = options.source_route.clone();
        save(&options.target_root, &execution)?;
    }
    Ok(())
}

pub fn retry(context: RewriteContext, id: &str) -> Result<RewriteActionEnvelope> {
    // Adopting a new batch may retire the previous failed invocation. Never
    // retry its frozen API selection against the replacement recording.
    RewriteStore::new(&context.target_root)?.load()?;
    let execution = load(&context.target_root)?.context("coordinator operation is absent")?;
    ensure!(
        execution.id == id && execution.finished && execution.error.is_some(),
        "retry requires the current failed coordinator operation"
    );
    if let Request::TargetQuality {
        api,
        gate_id,
        hardcode_ai_verified,
    } = &execution.request
    {
        // Old failed quality operations resume receipt admission, never another
        // coordinator-side check. Missing receipts route back to the integrator.
        let options = RewriteTargetQualityOptions {
            target_root: context.target_root.clone(),
            api: api.parse()?,
            gate_id: gate_id.clone(),
            hardcode_ai_verified: hardcode_ai_verified.clone(),
        };
        let store = RewriteStore::new(&context.target_root)?;
        let Some(lock) = store.try_lock()? else {
            return super::worker::runtime::current_envelope(&context.target_root);
        };
        let mut resolved =
            load(&context.target_root)?.context("coordinator operation is absent")?;
        ensure!(
            resolved.id == id && resolved.finished && resolved.error.is_some(),
            "coordinator operation changed before retry"
        );
        resolved.error = None;
        save(&context.target_root, &resolved)?;
        drop(lock);
        return super::target_quality::run(options);
    }
    start(&context.target_root, execution.request)
}

pub(super) fn retire_finished(target_root: &Path) -> Result<()> {
    if let Some(execution) = load(target_root)? {
        ensure!(
            execution.finished,
            "recover or finish the existing coordinator operation first"
        );
        fs::remove_file(path(target_root))?;
    }
    Ok(())
}

/// Called only after validating an explicitly selected replacement batch.
/// Old markers without a recording identity belong to the replaced snapshot.
pub(super) fn reconcile_recording_change(target_root: &Path, selected: &str) -> Result<bool> {
    let Some(execution) = load(target_root)? else {
        return Ok(true);
    };
    if !execution.finished {
        return Ok(execution.pid == std::process::id()
            && execution
                .recording_run_id
                .as_deref()
                .is_none_or(|id| id == selected));
    }
    if execution.recording_run_id.as_deref() != Some(selected) {
        fs::remove_file(path(target_root))?;
    }
    Ok(true)
}

pub(super) fn busy(target_root: &Path) -> Result<bool> {
    Ok(load(target_root)?.is_some_and(|execution| !execution.finished))
}

pub(super) fn owned_by_other_process(target_root: &Path) -> Result<bool> {
    Ok(load(target_root)?
        .is_some_and(|execution| !execution.finished && execution.pid != std::process::id()))
}

/// Observability for independently executable actions returned during background work.
pub(super) fn annotate_status(target_root: &Path, action: &mut RewriteAction) -> Result<()> {
    let Some(execution) = load(target_root)? else {
        return Ok(());
    };
    if execution.finished || execution.pid == std::process::id() || !alive(execution.pid) {
        return Ok(());
    }
    let Request::Next {
        execution_mode: mode,
        ..
    } = execution.request
    else {
        return Ok(());
    };
    match action {
        RewriteAction::WaitRequired {
            summary,
            execution_mode,
            ..
        }
        | RewriteAction::ImplementationRequired {
            summary,
            execution_mode,
            ..
        }
        | RewriteAction::WorkerStatusRequired {
            summary,
            execution_mode,
            ..
        }
        | RewriteAction::ExpertRequired {
            summary,
            execution_mode,
            ..
        } if execution_mode.is_none() => {
            *execution_mode = Some(mode);
            if mode == RewriteExecutionMode::AutoNext {
                *summary = format!("automatically advancing Replay; {summary}");
            }
        }
        _ => {}
    }
    Ok(())
}

/// Preserve the resource state of an already observed operation while projecting
/// one status response, even if its marker finishes during that projection.
pub(super) fn snapshot_blocks_replay(action: Option<&RewriteAction>) -> bool {
    matches!(action, Some(RewriteAction::WaitRequired { resource, .. })
        if resource == "coordinator_operation")
        || matches!(action, Some(RewriteAction::RecoveryRequired { .. }))
}

pub(super) fn status_action(target_root: &Path) -> Result<Option<RewriteAction>> {
    status_action_in_snapshot(target_root, None)
}

pub(super) fn status_action_for_state(
    target_root: &Path,
    state: &RewriteState,
) -> Result<Option<RewriteAction>> {
    status_action_in_snapshot(target_root, Some(state))
}

fn status_action_in_snapshot(
    target_root: &Path,
    state: Option<&RewriteState>,
) -> Result<Option<RewriteAction>> {
    let Some(execution) = load(target_root)? else {
        return Ok(None);
    };
    if execution.pid == std::process::id() && !execution.finished {
        return Ok(None);
    }
    if let Some(error) = execution.error {
        return Ok(Some(RewriteAction::ExecutionFailed {
            summary: format!(
                "coordinator operation failed; resolve the reported cause before retrying: {error}"
            ),
            operation_id: execution.id.clone(),
            retry: action::command(
                target_root,
                vec!["operation".into(), "retry".into(), execution.id],
                Vec::new(),
            ),
            status: action::status_command_for_api(target_root, None),
        }));
    }
    if execution.finished {
        return Ok(None);
    }
    if !alive(execution.pid) {
        return Ok(Some(action::recovery_required(target_root).action));
    }
    let execution_mode = match execution.request {
        Request::Next { execution_mode, .. } => Some(execution_mode),
        Request::TargetQuality { .. } => None,
    };
    let summary = running_summary(target_root, state);
    Ok(Some(RewriteAction::WaitRequired {
        execution_mode,
        summary: if execution_mode == Some(RewriteExecutionMode::AutoNext) {
            format!("automatically advancing Replay: {summary}")
        } else {
            summary
        },
        resource: "coordinator_operation".into(),
        requested_api: None,
        blocking_api: None,
        active_operation: None,
        retry_after_seconds: 30,
        status: action::status_command_for_api(target_root, None),
    }))
}

pub(super) fn recover(target_root: &Path) -> Result<()> {
    if let Some(execution) = load(target_root)? {
        ensure!(
            execution.finished || !alive(execution.pid),
            "coordinator operation is still running; inspect status"
        );
        if !execution.finished {
            fs::remove_file(path(target_root))?;
        }
    }
    Ok(())
}

pub(super) fn from_status(status: super::RewriteStatusReport) -> RewriteActionEnvelope {
    RewriteActionEnvelope {
        schema_version: status.schema_version,
        pending: status.pending,
        workflow: status.workflow,
        api_inventory: status.api_inventory,
        latest_focused_e2e: status.latest_focused_e2e,
        action: status.action,
        terminal_allowed: status.terminal_allowed,
    }
}

pub(super) fn worker_action_while_busy(
    target_root: &Path,
    state: &RewriteState,
) -> Option<RewriteActionEnvelope> {
    if super::repository_analysis::required_action(target_root, state)
        .ok()
        .flatten()
        .is_some()
    {
        return None;
    }
    let action = (if state.implementers.is_some() {
        super::implementer::action(target_root, state)
            .ok()
            .flatten()
    } else {
        None
    })
    .or_else(|| super::worker::scheduler::global_action(target_root, state, true))?;
    let mut envelope = action::envelope(target_root, state, action);
    envelope.pending = super::coordination::projected_details(
        target_root,
        state,
        &envelope.action,
        &envelope.action,
        true,
    )
    .pending();
    Some(envelope)
}

fn alive(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|pid| unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

fn running_summary(target_root: &Path, state: Option<&RewriteState>) -> String {
    let Ok(super::traffic_operation::TrafficOperationState::Live(active)) =
        super::traffic_operation::state(target_root)
    else {
        return "running coordinator operation".into();
    };
    // The status caller already loaded and refreshed this potentially large
    // snapshot. Standalone operation inspections retain their own fallback.
    let loaded = if state.is_none() {
        RewriteStore::new(target_root)
            .ok()
            .and_then(|store| store.load_snapshot().ok().flatten())
    } else {
        None
    };
    let state = state.or(loaded.as_ref());
    let methods = recorded_methods(
        state.and_then(|state| state.case_source.as_deref()),
        active.api.as_deref(),
    );
    traffic_summary(
        &active,
        replay_progress(target_root, state, &active),
        &methods,
    )
}

fn traffic_summary(
    active: &super::traffic_operation::TrafficOperationMarker,
    replay_progress: Option<crate::e2e_run::E2eActiveProgress>,
    recorded_methods: &[String],
) -> String {
    let api = recorded_api_label(active.api.as_deref(), recorded_methods);
    match active.kind {
        super::traffic_operation::TrafficOperationKind::Replay => match replay_progress {
            Some(crate::e2e_run::E2eActiveProgress::PreparingIndex) => {
                "Preparing dependency index".to_string()
            }
            Some(crate::e2e_run::E2eActiveProgress::PreparingReplay) => {
                "Preparing Replay".to_string()
            }
            Some(crate::e2e_run::E2eActiveProgress::StartingTarget) => {
                "Starting target container".to_string()
            }
            Some(crate::e2e_run::E2eActiveProgress::Building) => {
                format!("building target for {api}")
            }
            Some(crate::e2e_run::E2eActiveProgress::PreparingCase { completed, total })
            | Some(crate::e2e_run::E2eActiveProgress::Replaying { completed, total }) => {
                format!("replaying {api} ({completed}/{total})")
            }
            Some(crate::e2e_run::E2eActiveProgress::Finalizing) => {
                format!("finalizing replay for {api}")
            }
            Some(crate::e2e_run::E2eActiveProgress::GeneratingEvidence) => {
                format!("generating Replay evidence for {api}")
            }
            None => format!("replaying {api}"),
        },
    }
}

fn recorded_api_label(api: Option<&str>, methods: &[String]) -> String {
    let route = api
        .map(super::api_selector::public_api)
        .unwrap_or("the workflow");
    if !route.starts_with('/') {
        return route.into();
    }
    match methods {
        [] => route.into(),
        [method] => format!("{method} {route}"),
        _ => format!("[{}] {route}", methods.join(", ")),
    }
}

fn recorded_methods(case_source: Option<&Path>, api: Option<&str>) -> Vec<String> {
    let Some(route) = api
        .map(super::api_selector::public_api)
        .filter(|route| route.starts_with('/'))
    else {
        return Vec::new();
    };
    let Some(case_source) = case_source else {
        return Vec::new();
    };
    crate::recording_api::methods::load(case_source)
        .map(|index| crate::recording_api::methods::for_route(&index, route))
        .unwrap_or_default()
}

fn replay_progress(
    target_root: &Path,
    state: Option<&RewriteState>,
    active: &super::traffic_operation::TrafficOperationMarker,
) -> Option<crate::e2e_run::E2eActiveProgress> {
    let state = state?;
    let context = crate::E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source: state.case_source.as_ref()?.clone(),
        run_key: None,
    };
    if active.api.is_none() {
        return crate::e2e_run::workflow_active_progress(&context, active.started_at.parse().ok()?)
            .ok()
            .flatten();
    }
    crate::e2e_run::focused_active_progress(&context, state.group_id.as_deref()?)
        .ok()
        .flatten()
}

fn root(target_root: &Path) -> PathBuf {
    crate::internal_runtime::root(target_root).join("rewrite/operations")
}
fn path(target_root: &Path) -> PathBuf {
    root(target_root).join("current.json")
}
fn load(target_root: &Path) -> Result<Option<Execution>> {
    match fs::read(path(target_root)) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("invalid coordinator operation marker")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn save(target_root: &Path, execution: &Execution) -> Result<()> {
    let temporary = root(target_root).join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(execution)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path(target_root))?;
        fs::File::open(root(target_root))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod legacy_quality_tests;

#[cfg(test)]
mod tests;
