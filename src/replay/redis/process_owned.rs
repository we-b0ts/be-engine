//! Finite process reads retain their original evidence without ordering case work.
use super::*;

impl RedisReplayState {
    pub(in crate::replay) fn apply_finite_process_order(
        &mut self,
        rules: &[crate::BackgroundDependencyRuleConfig],
    ) {
        for exchange in &mut self.exchanges {
            if exchange.source != ReplaySource::Process
                || exchange.record.native.command != "GET"
                || exchange.record.native.outcome != DependencyExchangeOutcome::Response
                || exchange.record.native.session_setup
                || !exchange.record.native.replay_safe
                || !exchange.record.native.parse_warnings.is_empty()
                || exchange.record.native.cache_snapshot_rule.is_some()
                || exchange.record.native.cache_snapshot_hit
                || self.connection_scopes.is_stateful(exchange)
            {
                continue;
            }
            if rules.iter().any(|rule| {
                !rule.uses_redis_snapshot()
                    && redis_rule_matches(
                        rule,
                        exchange.record.native.target_port,
                        "GET",
                        &exchange.args,
                    )
            }) {
                // A proven process selector removes pooled-lane ordering only.
                // The independently attributed task retains finite responses and consumption.
                exchange.connection_independent = true;
            }
        }
    }
}
