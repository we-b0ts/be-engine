//! Finite Memcached delivery state and success/failure accounting.
use super::*;

#[cfg(test)]
mod tests;

impl MemcachedReplayState {
    pub(in crate::replay) fn has_case_in_flight(&self) -> bool {
        self.exchanges.iter().enumerate().any(|(index, e)| {
            e.source == ReplaySource::Case
                && matches!(
                    self.lifecycle.live_status(index, e.status),
                    ReplayExchangeStatus::Responding
                        | ReplayExchangeStatus::AwaitingClientTermination
                )
        })
    }

    pub(in crate::replay) fn has_in_flight(&self) -> bool {
        self.exchanges.iter().enumerate().any(|(index, e)| {
            matches!(
                self.lifecycle.live_status(index, e.status),
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
        })
    }

    pub(super) fn finish_exchange<T>(
        &mut self,
        matched: &MatchedMemcachedExchange,
        commit: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let exchange = self
            .exchanges
            .get_mut(matched.index)
            .context("claimed Memcached Source exchange disappeared")?;
        match self
            .lifecycle
            .finish(&matched.claim, &mut exchange.status, commit)
        {
            Finish::Committed(value) => {
                self.record_completed(matched);
                Ok(Some(value))
            }
            Finish::Failed(error) => {
                self.record_failure(
                    matched,
                    format!("Memcached delivery commit failed: {error:#}"),
                );
                Err(error)
            }
            Finish::Unchanged => Ok(None),
        }
    }

    fn record_completed(&mut self, matched: &MatchedMemcachedExchange) {
        self.refresh_global_report(matched.index);
        let case_id = matched.report.case_id.clone();
        push_success_detail(
            &mut self.events.matched_count,
            &mut self.events.matched,
            &mut self.events.matched_details,
            case_id.as_deref(),
            |target_event_index| {
                let mut report = matched.report.clone();
                report.target_event_index.get_or_insert(target_event_index);
                report
            },
        );
    }

    pub(super) fn fail_exchange(&mut self, matched: &MatchedMemcachedExchange, reason: String) {
        let Some(exchange) = self.exchanges.get_mut(matched.index) else {
            return;
        };
        if exchange.status.is_consumed() {
            // The finite Source delivery remains true. A later Target protocol
            // violation is an independent unsafe event and still fails its Case.
            self.record_failure(matched, reason);
            return;
        }
        if !self.lifecycle.fail(&matched.claim, &mut exchange.status) {
            return;
        }
        self.record_failure(matched, reason);
    }

    fn record_failure(&mut self, matched: &MatchedMemcachedExchange, reason: String) {
        self.refresh_global_report(matched.index);
        if let Some(case_id) = &matched.report.case_id {
            self.events.dirty_case_ids.insert(case_id.clone());
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
