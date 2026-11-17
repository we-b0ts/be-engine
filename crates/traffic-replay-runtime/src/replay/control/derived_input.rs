use super::*;
pub use traffic_engine::replay::control::derived_input::*;
pub(super) async fn accept<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Value {
    let outcome = async {
        let case = request
            .case_id
            .as_deref()
            .context("derived input requires case_id")?
            .to_owned();
        let registration = request
            .derived_input
            .as_ref()
            .context("derived input is unavailable")?;
        let owner = {
            let state = state.lock().await;
            ensure!(
                state.active_case_id.as_deref() == Some(case.as_str()),
                "derived input requires the active case"
            );
            state
                .replay_policy
                .as_ref()
                .context("derived input requires a policy")?
                .contracts()
                .clone()
        };
        let sent_at = registration.request_sent_at;
        let actual = registration.request.clone();
        let preparing = owner.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            preparing.prepare_derived_inputs(&case, sent_at, &actual)
        })
        .await
        .context("derived input reconstruction task failed")??;
        let state = state.lock().await;
        ensure!(
            state.active_case_id.as_deref() == request.case_id.as_deref(),
            "derived input case changed during reconstruction"
        );
        owner.commit_derived_inputs(prepared)
    }
    .await;
    match outcome {
        Ok(()) => serde_json::json!({"ok":true}),
        Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
    }
}
