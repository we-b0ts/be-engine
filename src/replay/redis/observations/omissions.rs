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
        !self.status.is_consumed()
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
