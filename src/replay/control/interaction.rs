//! Let started dependency exchanges finish within the interaction cleanup budget.

use super::*;
use anyhow::{Context, Result};
use std::time::Duration;

pub(super) async fn drain(
    state: &Arc<Mutex<ReplayState>>,
    case_id: &str,
    case_dir: &std::path::Path,
    post_response_window: Duration,
    observation_deadline: Option<tokio::time::Instant>,
) -> Result<bool> {
    let started = tokio::time::Instant::now();
    let request = case_dir.join("request.json");
    if !request.exists() {
        return Ok(false);
    }
    #[derive(Deserialize)]
    struct Input {
        interaction: Option<crate::interaction::model::InputTranscript>,
    }
    let input: Input =
        serde_json::from_slice(&crate::request_headers::load_request_file(&request)?)
            .context("invalid interaction request metadata")?;
    let Some(transcript) = input.interaction else {
        return Ok(false);
    };
    transcript.validate()?;
    // Closing the primary transport and waiting for its business dependencies
    // have different budgets. New tail evidence retains the case until its
    // absolute request deadline; legacy recordings keep the cleanup bound.
    let deadline = observation_deadline
        .unwrap_or_else(|| started + Duration::from_millis(transcript.policy.cleanup_timeout_ms));
    // The same fixed attribution window applies to ordinary and streaming cases.
    // Completion only waits for exchanges already delivering data; background
    // calls after this boundary remain subject to the existing Replay policy.
    tokio::time::timeout_at(deadline, tokio::time::sleep(post_response_window))
        .await
        .context("interaction cleanup window timed out; case ownership was retained")?;
    loop {
        let now = tokio::time::Instant::now();
        let state = state.lock().await;
        anyhow::ensure!(
            state.active_case_id.as_deref() == Some(case_id),
            "interaction case ownership changed during cleanup"
        );
        // Policy-owned Global work can span cases. Keep all Case-source
        // deliveries here, including source aliases claimed by another case;
        // only whole-session finalization waits for both scopes.
        let in_flight = state.mysql.exchanges.iter().any(|exchange| {
            exchange.source == ReplaySource::Case
                && matches!(
                    exchange.status,
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        }) || state.redis.has_case_in_flight()
            || state.memcached.has_case_in_flight()
            || state.motan.has_case_in_flight()
            || state.http_has_case_in_flight();
        drop(state);
        if !in_flight {
            return Ok(true);
        }
        anyhow::ensure!(
            now < deadline,
            "interaction dependency cleanup timed out; case ownership was retained"
        );
        tokio::time::sleep(Duration::from_millis(25).min(deadline.saturating_duration_since(now)))
            .await;
    }
}
