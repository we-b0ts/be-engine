//! Permission to omit transient observations is separate from real wire delivery.
use super::*;

#[derive(Debug, Clone, Serialize)]
pub(in crate::replay) struct OmissionAudit {
    rule_id: String,
    reason: &'static str,
    source_witness: crate::replay::report::command::CommandExchangeRefReport,
}

impl ReplayExchange {
    pub(in crate::replay::redis) fn requires_delivery(&self) -> bool {
        !self.status.is_covered()
            && !(self.optional_observation_rule.is_some() && self.status.is_available())
    }
}

impl RedisReplayState {
    pub(in crate::replay::redis) fn allowed_state_omission_count(&self) -> usize {
        self.exchanges
            .iter()
            .filter(|e| e.optional_observation_rule.is_some() && e.status.is_available())
            .count()
    }
    pub(in crate::replay::redis) fn allowed_state_omissions(&self) -> Vec<OmissionAudit> {
        self.exchanges
            .iter()
            .filter(|e| e.optional_observation_rule.is_some() && e.status.is_available())
            .take(1000)
            .map(|e| OmissionAudit {
                rule_id: e.optional_observation_rule.clone().unwrap(),
                reason: "source_proven_transient_nil",
                source_witness: crate::replay::report::command::CommandExchangeRefReport {
                    case_id: e.case_id.clone(),
                    source: e.source,
                    connection_id: e.record.connection_id,
                    sequence: e.record.sequence,
                    command: e.record.command.clone(),
                },
            })
            .collect()
    }
}

impl RedisReplayState {
    pub(in crate::replay) fn open_socketio_eof_suffix(&mut self, index: usize) {
        let exchange = &mut self.exchanges[index];
        if exchange.status == ReplayExchangeStatus::Available
            && exchange.source == ReplaySource::Case
            && exchange.shared_rule_id.is_none()
            && !exchange.reusable_snapshot
            && !exchange.subscription_alias
            && exchange.record.outcome == crate::DependencyExchangeOutcome::Response
            && exchange.record.replay_safe
            && exchange.record.parse_warnings.is_empty()
        {
            exchange.status = ReplayExchangeStatus::SocketIoEofSuffix;
        }
    }

    pub(in crate::replay) fn notify_socketio_eof_suffix(&self) {
        self.lifecycle.notify_waiters();
    }

    pub(in crate::replay) fn settle_socketio_eof_suffix(
        &mut self,
        index: usize,
        omit: bool,
    ) -> bool {
        let exchange = &mut self.exchanges[index];
        if exchange.status == ReplayExchangeStatus::SocketIoEofSuffix {
            exchange.status = ReplayExchangeStatus::Available;
        }
        if omit && exchange.status == ReplayExchangeStatus::Available && !exchange.reusable_snapshot
        {
            exchange.status = ReplayExchangeStatus::OmittedAfterSocketIoEof;
            return true;
        }
        false
    }

    pub(in crate::replay) fn record_unmatched_request(&mut self, report: CommandRequestReport) {
        if let Some(case) = &report.case_id {
            self.events.dirty_case_ids.insert(case.clone());
        }
        self.events.unmatched.push(report);
    }
}
