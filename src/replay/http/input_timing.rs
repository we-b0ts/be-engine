//! Native HTTP adapters expose only immutable stream clocks and actual flush progress.
use super::*;
use crate::replay::control::http_input_timing::{BoundStream, SourceStream};
use anyhow::ensure;

pub(in crate::replay) fn source_streams(
    state: &ReplayState,
    case: &str,
) -> Result<Vec<SourceStream>> {
    let plan = state
        .case_execution_plans
        .get(case)
        .context("HTTP timing execution plan missing")?;
    let mut streams = Vec::new();
    for &index in plan.native.protocols[&traffic_protocol::ProtocolId::new("http")]
        .members
        .iter()
    {
        let exchange = &state.protocols.http_exchanges[index];
        let record = &exchange.record;
        let Some(stream) = &record.native.response_stream else {
            continue;
        };
        ensure!(
            stream.complete
                && record
                    .native
                    .response_status
                    .is_some_and(|s| (200..300).contains(&s))
                && record.lifecycle_stop.is_none()
                && record.native.outcome == crate::DependencyExchangeOutcome::Response,
            "shared HTTP timing requires complete successful dependency streams"
        );
        streams.push(SourceStream {
            index,
            started_at: record
                .native
                .request_started_at
                .context("HTTP stream request clock missing")?,
            stream: stream.clone(),
        });
    }
    Ok(streams)
}

pub(super) async fn bind(
    state: &Arc<Mutex<ReplayState>>,
    detail: Option<&MatchedHttpExchangeReport>,
    progress: crate::http::termination::DeliveryProgress,
) -> Result<Option<BoundStream>> {
    let state = state.lock().await;
    match (state.protocols.http_input_timing.as_ref(), detail) {
        (Some(timeline), Some(detail))
            if detail.case_id.as_deref() == state.active_case_id.as_deref() =>
        {
            timeline.bind(detail.index, progress)
        }
        _ => Ok(None),
    }
}
