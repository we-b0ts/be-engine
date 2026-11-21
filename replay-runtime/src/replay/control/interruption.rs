//! Freeze diagnostic observations without releasing cases or finalizing Replay.
use super::*;

pub(super) async fn publish<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    path: Option<&Path>,
) -> Value {
    match snapshot(state, path).await {
        Ok(()) => serde_json::json!({
            "ok":true,"interrupted":true,"finalized":false,"complete":false
        }),
        Err(error) => serde_json::json!({
            "ok":false,"error":format!("failed to preserve interrupted Replay evidence: {error:#}")
        }),
    }
}

async fn snapshot<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    path: Option<&Path>,
) -> Result<()> {
    let path = path.context("interrupted Replay requires a configured report path")?;
    if let Err(error) = policy::await_durable(&state).await {
        tracing::warn!(error=%error,"publishing incomplete interrupted hypothesis evidence");
    }
    let report = {
        let state = state.lock().await;
        ensure!(
            state.finalized_at.is_none(),
            "cannot replace finalized Replay evidence with an interruption"
        );
        // Seal the observations actually captured, not the execution. In-flight
        // exchanges, active ownership and pending cases retain their real states.
        state.target_observations.seal()?;
        let mut report = serde_json::to_value(state.snapshot_report())?;
        report["interrupted"] = true.into();
        report["interrupted_at"] = serde_json::to_value(Utc::now())?;
        report["complete"] = false.into();
        report
    };
    let providers = state.lock().await.providers.clone();
    write_final_report_value(path.to_path_buf(), &report, providers.report_codecs()).await
}
