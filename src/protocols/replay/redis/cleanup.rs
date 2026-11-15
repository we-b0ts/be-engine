//! Bounded Source references for actual failure-cleanup blockers, without values.
use super::*;
use serde_json::{Value, json};

impl RedisReplayState {
    pub(crate) fn case_in_flight_diagnostic(&self) -> Value {
        let pending = self.exchanges.iter().enumerate().filter(|(index, e)| {
            e.source == ReplaySource::Case
                && !self.append_streams.idle_source(*index)
                && matches!(
                    self.lifecycle.live_status(*index, e.status),
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        });
        let count = pending.clone().count();
        let references = pending
            .take(4)
            .map(|(index, e)| {
                json!({"index":index, "case_id":e.case_id,
                "connection_id":e.record.native.connection_id, "sequence":e.record.native.sequence,
                "status":format!("{:?}", self.lifecycle.live_status(index,e.status))})
            })
            .collect::<Vec<_>>();
        json!({"count":count, "references":references, "omitted":count.saturating_sub(4),
            "pubsub_inputs":self.pubsub.case_delivery_diagnostic(),
            "observations":self.observations.in_flight_diagnostic(),
            "activity_refreshes":self.activity_refresh.in_flight_diagnostic()})
    }
}
