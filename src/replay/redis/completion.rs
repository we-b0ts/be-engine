//! Native Redis commit hooks run inside the common finite delivery transaction.
use super::*;

impl MatchedRedisExchange {
    pub(super) fn publish_wire(&self) {
        if let Claim::Finite(ticket) = &self.claim {
            ticket.publish_wire();
        }
    }
}

impl RedisReplayState {
    /// A caller of this hook asserts successful native wire/termination delivery.
    /// Response contracts use finish_delivery so their commit shares the same
    /// transaction as the terminal transition.
    pub(super) fn complete_exchange(&mut self, matched: &MatchedRedisExchange) -> bool {
        match &matched.claim {
            Claim::Finite(ticket) => {
                self.lifecycle.wire_delivered(ticket);
                if !self
                    .lifecycle
                    .complete(ticket, &mut self.exchanges[matched.index].status)
                {
                    return false;
                }
                self.exchanges[matched.index].matched_once = true;
            }
            Claim::Native(kind) => {
                match kind {
                    NativeClaimKind::ActivityRefresh => {
                        self.complete_activity(matched.refresh.as_ref().expect("activity claim"))
                    }
                    NativeClaimKind::AppendStream => {
                        self.complete_append(matched.append.as_ref().expect("append claim"))
                    }
                    NativeClaimKind::StateObservation => self.complete_observation(
                        matched.observation.as_ref().expect("observation claim"),
                        matched.index,
                    ),
                    NativeClaimKind::ReusableSnapshot => {
                        self.exchanges[matched.index].matched_once = true
                    }
                }
                self.lifecycle.notify_waiters();
            }
        }
        self.record_completion(matched);
        true
    }

    fn record_completion(&mut self, matched: &MatchedRedisExchange) {
        if matches!(matched.claim, Claim::Finite(_))
            && let Some(refresh) = &matched.refresh
        {
            self.complete_finite_activity(refresh);
        }
        self.complete_closed_expiry(matched);
        self.refresh_global_report(matched.index);
        let case_id = matched.report.case_id.clone();
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            &mut self.events.matched_details,
            case_id.as_deref(),
            |_| matched.report.clone(),
        );
    }

    pub(super) fn finish_delivery(
        &mut self,
        matched: &MatchedRedisExchange,
        response: &[u8],
        rendered_at: chrono::DateTime<chrono::Utc>,
        delivered_at: chrono::DateTime<chrono::Utc>,
        published: Result<()>,
    ) -> Result<()> {
        let Claim::Finite(ticket) = &matched.claim else {
            anyhow::bail!("finite response commit requires its shared claim");
        };
        let contracts = &self.request_contracts;
        let exchange = &mut self.exchanges[matched.index];
        let finish = self.lifecycle.finish(ticket, &mut exchange.status, || {
            published?;
            if let Some(delivery) = &matched.read_back {
                contracts.commit_redis_read_back(delivery, delivered_at)?;
            }
            if let Some(delivery) = &matched.unified_delivery {
                contracts.commit_redis_delivery(delivery, response, rendered_at)?;
            }
            if let Some(read) = &matched.time_read {
                contracts.record_redis_time_read_witness(
                    read,
                    Some(&exchange.response),
                    response,
                    delivered_at,
                )?;
            }
            Ok(())
        });
        match finish {
            Finish::Committed(()) => {
                self.exchanges[matched.index].matched_once = true;
                self.record_completion(matched);
                Ok(())
            }
            Finish::Failed(error) => {
                self.record_failure(matched, error.to_string());
                Err(error)
            }
            Finish::Unchanged => anyhow::bail!("finite Redis delivery claim is no longer active"),
        }
    }

    pub(super) fn fail_exchange(&mut self, matched: &MatchedRedisExchange, reason: String) {
        let status = &mut self.exchanges[matched.index].status;
        if matches!(matched.claim, Claim::Finite(_)) && status.is_consumed() {
            // A new post-EOF violation cannot undo already delivered evidence.
            self.record_failure(matched, reason);
            return;
        }
        match &matched.claim {
            Claim::Finite(ticket) => {
                if !self.lifecycle.fail(ticket, status) {
                    return;
                }
            }
            Claim::Native(_) => {
                if *status == ReplayExchangeStatus::Failed {
                    return;
                }
                *status = ReplayExchangeStatus::Failed;
                self.lifecycle.notify_waiters();
            }
        }
        self.record_failure(matched, reason);
    }

    fn record_failure(&mut self, matched: &MatchedRedisExchange, reason: String) {
        self.fail_closed_expiry(matched.index);
        if let Some(refresh) = &matched.refresh {
            self.fail_activity(refresh);
        }
        if let Some(append) = &matched.append {
            self.fail_append(append);
        }
        if let Some(observation) = &matched.observation {
            self.fail_observation(observation);
        }
        self.refresh_global_report(matched.index);
        if let Some(case) = &matched.report.case_id {
            self.events.dirty_case_ids.insert(case.clone());
        }
        self.events.unsafe_events.push(CommandRequestReport {
            target_observation_id: None,
            case_id: matched.report.case_id.clone(),
            target: matched.report.target.clone(),
            command: matched.report.command.clone(),
            target_event_index: matched.report.target_event_index,
            request_fingerprint: None,
            reason,
            diagnostic: None,
        });
    }
}
