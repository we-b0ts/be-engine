//! Freeze diagnostic observations without releasing cases or finalizing Replay.
use super::*;

pub(super) async fn publish(state: Arc<Mutex<ReplayState>>, path: Option<&Path>) -> Value {
    match snapshot(state, path).await {
        Ok(()) => serde_json::json!({
            "ok":true,"interrupted":true,"finalized":false,"complete":false
        }),
        Err(error) => serde_json::json!({
            "ok":false,"error":format!("failed to preserve interrupted Replay evidence: {error:#}")
        }),
    }
}

async fn snapshot(state: Arc<Mutex<ReplayState>>, path: Option<&Path>) -> Result<()> {
    let path = path.context("interrupted Replay requires a configured report path")?;
    let report = {
        let state = state.lock().await;
        ensure!(
            state.finalized_at.is_none(),
            "cannot replace finalized Replay evidence with an interruption"
        );
        // Seal the observations actually captured, not the execution. In-flight
        // exchanges, active ownership and pending cases retain their real states.
        if let Some(policy) = &state.replay_policy {
            policy.request_contracts.seal_witnesses()?;
        }
        let mut report = serde_json::to_value(state.snapshot_report())?;
        report["interrupted"] = true.into();
        report["interrupted_at"] = serde_json::to_value(Utc::now())?;
        report["complete"] = false.into();
        report
    };
    write_final_report_value(path.to_path_buf(), &report).await
}
