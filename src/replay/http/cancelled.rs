//! Real dependency transport cancellation after an independently delivered primary close.
use super::*;
use crate::http::termination::ClientTermination;
use crate::replay::control::http_input_timing::Timeline;

pub(super) struct Observation {
    timeline: Arc<Timeline>,
    transport: ClientTermination,
    source_chunks: usize,
    prefix_chunks: usize,
    pub queued_chunks: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct Audit {
    case_id: Option<String>,
    source_http_index: usize,
    reason: &'static str,
    source_chunks: usize,
    required_pre_close_chunks: usize,
    queued_chunks: usize,
    recorded_eof_delivered: bool,
    observed_termination: crate::dependency::DependencyTermination,
}

impl ReplayState {
    pub(in crate::replay) fn permits_cancelled_http_omission(&self, index: usize) -> bool {
        self.protocols
            .http_exchanges
            .get(index)
            .is_some_and(|e| e.status == super::super::ReplayExchangeStatus::Cancelled)
            && self.protocols.http_events.cancelled.contains_key(&index)
    }
}

impl Observation {
    pub(super) fn new(
        timeline: Arc<Timeline>,
        transport: ClientTermination,
        source_chunks: usize,
        prefix_chunks: usize,
    ) -> Self {
        Self {
            timeline,
            transport,
            source_chunks,
            prefix_chunks,
            queued_chunks: 0,
        }
    }

    async fn observe(&self, index: usize) -> Option<crate::dependency::DependencyTermination> {
        let mut events = self.transport.subscribe();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            self.timeline.wait_closed().await;
            loop {
                if self.transport.engine_stopped() {
                    return None;
                }
                // This path already owns an unfinished BodyDrop. A genuine
                // post-close FIN is admissible too, retaining its write-half
                // scope in the audit rather than promoting it to a reset.
                if let Some(end) = self
                    .transport
                    .cancelled()
                    .or_else(|| self.transport.observed())
                {
                    if self.timeline.permits_cancellation(index, end.at) {
                        return Some(end.termination);
                    }
                    if end.termination.scope == crate::dependency::TerminationScope::Connection {
                        return None;
                    }
                }
                if events.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
}

pub(super) fn finish(
    state: Arc<Mutex<ReplayState>>,
    detail: MatchedHttpExchangeReport,
    observation: Observation,
) {
    tokio::spawn(async move {
        let end = observation.observe(detail.index).await;
        let mut state = state.lock().await;
        if let Some(end) =
            end.filter(|_| state.finalized_at.is_none() && detail.case_id == state.active_case_id)
        {
            let audit = Audit {
                case_id: detail.case_id.clone(),
                source_http_index: detail.index,
                reason: "dependency_cancelled_after_primary_client_close",
                source_chunks: observation.source_chunks,
                required_pre_close_chunks: observation.prefix_chunks,
                queued_chunks: observation.queued_chunks,
                recorded_eof_delivered: false,
                observed_termination: end,
            };
            let exchange = &mut state.protocols.http_exchanges[detail.index];
            exchange.time_copy_delivery = None;
            exchange.status = super::super::ReplayExchangeStatus::Cancelled;
            state
                .protocols
                .http_events
                .cancelled
                .insert(detail.index, audit);
            state.complete_http_exchange(detail);
        } else {
            tracing::warn!(case_id = ?detail.case_id, source_http_index = detail.index,
                queued_chunks = observation.queued_chunks,
                cancellation = %observation.timeline.cancellation_diagnosis(&observation.transport),
                "HTTP stream cancellation was not independently proven");
            state.finish_http_response(
                detail,
                Err(anyhow!(
                    "Target HTTP dependency body was dropped before complete delivery"
                )),
            );
        }
    });
}
