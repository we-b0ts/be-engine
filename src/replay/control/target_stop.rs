//! A Source shutdown is an engine-owned session boundary, before Case release.
use super::*;

pub(super) async fn prepare(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<ReplayState>>,
) -> Value {
    let result = async {
        let case = request
            .case_id
            .as_deref()
            .context("prepare_end requires case_id")?;
        {
            let state = state.lock().await;
            ensure!(
                state.active_case_id.as_deref() == Some(case),
                "prepare_end requires the active Case"
            );
        }
        let required = dependency_tail::target_stop_required(state, case).await;
        if required {
            dependency_tail::prepare_target_stop(state, case).await?;
            let mut state = state.lock().await;
            ensure!(
                state.active_case_id.as_deref() == Some(case),
                "Case changed while preparing Target stop"
            );
            state.target_stop_prepared.insert(case.into());
        }
        Ok::<_, anyhow::Error>(serde_json::json!({"ok":true,"target_stop_required":required}))
    }
    .await;
    result.unwrap_or_else(|error| serde_json::json!({"ok":false,"error":format!("{error:#}")}))
}

/// Only the engine's trusted controller sends end_stopped, after its runtime
/// stop receipt. Ordinary end cannot release this Case or admit another input.
pub(super) async fn confirm(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<ReplayState>>,
) -> Result<bool> {
    let case = request.case_id.as_deref().context("end requires case_id")?;
    let mut state = state.lock().await;
    let required = state.dependency_tails.target_stop_required(case);
    if !required {
        ensure!(
            request.command != "end_stopped",
            "Case has no Source shutdown boundary"
        );
        return Ok(false);
    }
    ensure!(
        request.command == "end_stopped" && state.target_stop_prepared.contains(case),
        "Case requires prepare_end, confirmed Target process stop, then end_stopped before releasing ownership"
    );
    ensure!(
        state.active_case_id.as_deref() == Some(case),
        "stopped Target requires the active Case"
    );
    state.target_session_stopped = true;
    Ok(true)
}
