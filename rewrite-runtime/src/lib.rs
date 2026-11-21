//! Rewrite traffic reservations and policy-evidence admission.
use anyhow::{Result, ensure};
use std::path::Path;
pub use traffic_engine_environment::internal_runtime;
pub use traffic_rewrite_model::rewrite::{action, api_selector, model};
pub mod traffic_operation;
pub fn ensure_not_replaying(target: &Path, api: &str) -> Result<()> {
    if let traffic_operation::TrafficOperationState::Live(active) =
        traffic_operation::state(target)?
    {
        ensure!(
            active.api.as_deref().is_some_and(
                |selected| api_selector::public_api(selected) != api_selector::public_api(api)
            ),
            "rule evidence for {api} is unavailable while its Replay is reserved or running; wait for that attempt to finish"
        );
    }
    Ok(())
}
