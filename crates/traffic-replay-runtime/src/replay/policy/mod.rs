use anyhow::Result;
pub use traffic_engine::replay::policy::*;
pub(crate) async fn await_durable<P: crate::replay::protocol_runtime::ReplayProtocolSet>(
    state: &tokio::sync::Mutex<crate::replay::RuntimeState<P>>,
) -> Result<()> {
    let owner = state
        .lock()
        .await
        .replay_policy
        .as_ref()
        .map(|policy| policy.contracts().clone());
    if let Some(owner) = owner {
        owner.await_hypotheses_durable().await?;
    }
    Ok(())
}
