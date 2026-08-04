use anyhow::Result;

use super::model::{RewritePhase, RewriteRecoveryReport};
use super::store::RewriteStore;
use super::{RewriteContext, action, artifacts, recording_execution, traffic_operation};
use crate::{E2eRunContext, ManagedRecordingOperation};

pub(super) async fn recover(context: RewriteContext) -> Result<RewriteRecoveryReport> {
    let (target_root, _) = crate::e2e_run::resolve_project(&context.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let recording_execution_state = recording_execution::state(&target_root)?;
    if let recording_execution::RecordingExecutionState::Live(marker) = &recording_execution_state {
        anyhow::bail!(
            "recording executor process {} is still active; inspect `backend-rewrite status`",
            marker.pid
        );
    }
    if let traffic_operation::TrafficOperationState::Live(marker) =
        traffic_operation::state(&target_root)?
    {
        anyhow::bail!(
            "traffic {:?} process {} is still active; inspect `backend-rewrite status`",
            marker.kind,
            marker.pid
        );
    }
    let recovered_stale_traffic_operation = traffic_operation::clear_stale(&target_root)?;
    let recording_executor_stale = matches!(
        recording_execution_state,
        recording_execution::RecordingExecutionState::Stale(_)
    );
    let recovered_stale_lock = store.recover_lock()?;
    let _lock = store.lock()?;
    let mut state = store.load()?;
    let mut recovered_recording_run = None;
    let mut replacement_recording_run = None;
    let mut removed_managed_containers = 0;
    if let Some(state) = state.as_mut() {
        let recording = match state.phase {
            RewritePhase::RecordingRequired => Some((
                ManagedRecordingOperation::Record,
                state.recording_run_id.clone(),
                artifacts::standard_recording_publication(&target_root, &state.recording_run_id)
                    .unwrap_or(artifacts::RecordingPublication::Running),
            )),
            RewritePhase::ComparisonRecordingRequired => {
                state.comparison_run_id.clone().map(|run_id| {
                    let publication =
                        artifacts::comparison_recording_publication(&target_root, &run_id)
                            .unwrap_or(artifacts::RecordingPublication::Running);
                    (
                        ManagedRecordingOperation::RecordComparison,
                        run_id,
                        publication,
                    )
                })
            }
            _ => None,
        };
        if let Some((operation, run_id, publication)) = recording
            && (recovered_stale_lock
                || recording_executor_stale
                || publication == artifacts::RecordingPublication::Running)
        {
            let recovery =
                crate::recover_managed_recording(&target_root, operation, &run_id).await?;
            removed_managed_containers = recovery.removed_containers;
            recording_execution::clear_stale(&target_root)?;
            recovered_recording_run = Some(run_id.clone());
            if publication != artifacts::RecordingPublication::Finalized {
                let replacement =
                    artifacts::allocate_run_id_excluding(&target_root, operation, &[&run_id])?;
                match operation {
                    ManagedRecordingOperation::Record => {
                        state.recording_run_id = replacement.clone();
                        state.recording_rejection = Some(
                            "previous standard recording was interrupted before finalization"
                                .to_string(),
                        );
                    }
                    ManagedRecordingOperation::RecordComparison => {
                        state.comparison_run_id = Some(replacement.clone());
                        state.comparison_rejection = Some(
                            "previous comparison recording was interrupted before finalization"
                                .to_string(),
                        );
                    }
                }
                state.bump();
                replacement_recording_run = Some(replacement);
                store.save(state)?;
            }
        }
    }
    let recovered_focused_attempt = match state {
        Some(state) => match (state.case_source.clone(), state.group_id.clone()) {
            (Some(case_source), Some(group_id)) => {
                crate::e2e_run::recover_focused_e2e_api(
                    E2eRunContext {
                        target_root: target_root.clone(),
                        case_source,
                        run_key: None,
                    },
                    &group_id,
                )
                .await?
            }
            _ => false,
        },
        None => false,
    };
    Ok(RewriteRecoveryReport {
        recovered_stale_lock,
        recovered_stale_traffic_operation,
        recovered_focused_attempt,
        recovered_recording_run,
        replacement_recording_run,
        removed_managed_containers,
        next: action::next_command(&target_root),
    })
}
