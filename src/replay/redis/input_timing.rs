//! Redis timing projection and the distinct response-written completion fact.
use super::*;
use crate::replay::control::input_timing::{DeliveryReference, Evidence};
use chrono::{DateTime, Utc};

impl RedisReplayState {
    pub(in crate::replay) fn timing_evidence(
        &self,
        case: &str,
        start: DateTime<Utc>,
    ) -> (Vec<Evidence>, bool) {
        let mut evidence = Vec::new();
        let mut covered = true;
        for exchange in self
            .exchanges
            .iter()
            .filter(|e| e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case))
        {
            let record = &exchange.record;
            if record.lifecycle_cleanup
                || record.session_setup
                || exchange.reusable_snapshot
                || record.cache_snapshot_hit
            {
                continue;
            }
            let Some(at) = record.timestamp else {
                covered = false;
                continue;
            };
            if at < start {
                continue;
            }
            if record.outcome != DependencyExchangeOutcome::Response {
                covered = false;
                continue;
            }
            evidence.push(Evidence {
                reference: DeliveryReference::RedisResponse(record.cleanup_reference()),
                completed_at: at,
            });
        }
        let (pushes, pushes_covered) = self.pubsub.timing_evidence(case, start);
        evidence.extend(pushes);
        (evidence, covered && pushes_covered)
    }
}

pub(super) fn response_delivered(
    state: &mut ReplayState,
    matched: &MatchedRedisExchange,
    scope: Option<&(String, DateTime<Utc>)>,
) {
    let Some((case, epoch)) = scope else {
        return;
    };
    if state.active_case_id.as_deref() != Some(case)
        || state.target_session_stopped
        || state.finalized_at.is_some()
    {
        return;
    }
    let exchange = &state.redis.exchanges[matched.index];
    if exchange.source != ReplaySource::Case || exchange.case_id.as_deref() != Some(case) {
        return;
    }
    if let Some(timeline) = &mut state.input_timing {
        timeline.delivered(
            case,
            *epoch,
            DeliveryReference::RedisResponse(exchange.record.cleanup_reference()),
        );
    }
}
