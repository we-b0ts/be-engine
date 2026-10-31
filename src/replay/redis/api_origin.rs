//! Proven foreign API work must not impose order on the active request's Redis calls.
use super::*;
use std::path::Path;
use tracing::info;

impl RedisReplayState {
    pub(in crate::replay) fn apply_api_origin_order(
        &mut self,
        source: &Path,
        rules: &[crate::BackgroundDependencyRuleConfig],
    ) -> Result<()> {
        // A current-format session has already frozen independently proved
        // ownership. Selector rediscovery cannot override its lane obligations.
        if crate::dependency_index::recording::root(source).is_some() {
            return Ok(());
        }
        let rules: Vec<_> = rules
            .iter()
            .filter(|rule| {
                matches!(rule, crate::BackgroundDependencyRuleConfig::Redis { .. })
                    && rule.trigger_source().is_some()
            })
            .cloned()
            .collect();
        if rules.is_empty()
            || !self
                .exchanges
                .iter()
                .any(|exchange| exchange.source == ReplaySource::Case)
        {
            return Ok(());
        }

        // Origin discovery includes unselected trigger cases in the completed
        // recording. Key shape alone never establishes foreign ownership.
        let origins = crate::api_trigger::load(source, &rules)?;
        let mut independent = 0;
        for exchange in &mut self.exchanges {
            if exchange.source != ReplaySource::Case || self.connection_scopes.is_stateful(exchange)
            {
                continue;
            }
            let Some(case_id) = exchange.case_id.as_deref() else {
                continue;
            };
            let event = serde_json::to_value(&exchange.record)?;
            if origins
                .witness(case_id, &event)
                .is_some_and(|witness| !witness.same_resource_read)
            {
                // Low-level synthetic fixture ordering preserves finite inventory.
                exchange.connection_independent = true;
                independent += 1;
            }
        }
        if independent > 0 {
            info!(
                exchanges = independent,
                "applied proven foreign API Redis ordering"
            );
        }
        Ok(())
    }
}
