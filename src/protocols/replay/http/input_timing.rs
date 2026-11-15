//! Native HTTP adapters expose only immutable stream clocks and actual flush progress.
use super::*;
use crate::replay::ProtocolExchange;
use crate::replay::control::primary_close::BoundStream;
use crate::replay::protocol_runtime::primary_close::SourceStream;
use anyhow::ensure;

pub(crate) fn source_streams(state: &ReplayState, case: &str) -> Result<Vec<SourceStream>> {
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
            reference: ProtocolExchange {
                inventory: ReplayProtocol::Http.id(),
                index,
            },
            started_at: record
                .native
                .request_started_at
                .context("HTTP stream request clock missing")?,
            headers_ms: stream.headers_ms,
            chunks_ms: stream.chunks.iter().map(|chunk| chunk.at_ms).collect(),
            end_ms: stream.end_ms,
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
    match (state.primary_close_timing.as_ref(), detail) {
        (Some(timeline), Some(detail))
            if detail.case_id.as_deref() == state.active_case_id.as_deref() =>
        {
            timeline.bind(
                ProtocolExchange {
                    inventory: ReplayProtocol::Http.id(),
                    index: detail.index,
                },
                progress,
            )
        }
        _ => Ok(None),
    }
}
