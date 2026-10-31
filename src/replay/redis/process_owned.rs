//! Finite process reads retain their original evidence without ordering case work.
use super::*;

impl RedisReplayState {
    pub(in crate::replay) fn apply_finite_process_order(
        &mut self,
        rules: &[crate::BackgroundDependencyRuleConfig],
    ) {
        for exchange in &mut self.exchanges {
            if exchange.source != ReplaySource::Process
                || exchange.record.command != "GET"
                || exchange.record.outcome != DependencyExchangeOutcome::Response
                || exchange.record.session_setup
                || !exchange.record.replay_safe
                || !exchange.record.parse_warnings.is_empty()
                || exchange.record.cache_snapshot_rule.is_some()
                || exchange.record.cache_snapshot_hit
                || self.connection_scopes.is_stateful(exchange)
            {
                continue;
            }
            if rules.iter().any(|rule| {
                !rule.uses_redis_snapshot()
                    && redis_rule_matches(rule, exchange.record.target_port, "GET", &exchange.args)
            }) {
                // A proven process selector removes pooled-lane ordering only.
                // The independently attributed task retains finite responses and consumption.
                exchange.connection_independent = true;
            }
        }
    }
}
