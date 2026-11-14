//! Global response bodies are re-read through the shared immutable byte cache.
use super::*;
use crate::dependency_index::RecordRef;

impl RedisReplayState {
    pub(crate) fn register_global_exchange(
        &mut self,
        record: RecordedExchange,
        source_kind: ReplaySource,
        reference: RecordRef,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        rules: &[crate::BackgroundDependencyRuleConfig],
    ) -> Result<()> {
        let identity = (record.connection_id, record.sequence);
        self.register_exchange(record, source_kind, None, targets, rules)?;
        if let Some(exchange) = self.exchanges.last_mut()
            && (exchange.record.connection_id, exchange.record.sequence) == identity
            && exchange.source.is_run_owned()
        {
            exchange.response_evidence = Some(reference);
            exchange.response = Vec::new();
            exchange.record.response.data = String::new();
        }
        Ok(())
    }
}

impl ReplayExchange {
    pub(super) fn response_bytes(&self) -> Result<Vec<u8>> {
        match &self.response_evidence {
            Some(reference) => reference.load::<RecordedExchange>()?.response.decode(),
            None => Ok(self.response.clone()),
        }
    }
}

impl RedisReplayState {
    pub(in crate::replay) fn visit_global_regular_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in unused_iter(&self.exchanges, ReplaySource::Startup) {
            visitor(serde_json::to_value(item)?)?;
        }
        self.pubsub.visit_global_inline_unused(visitor)?;
        Ok(())
    }

    pub(in crate::replay) fn global_notification_evidence(
        &self,
    ) -> Result<pubsub::NotificationSessionEvidence> {
        self.pubsub.notification_evidence(&self.exchanges)
    }
    pub(in crate::replay) fn global_unused_count(&self) -> usize {
        if let Some(count) = self.global_regular_report_count() {
            return count
                + self.global_report_extra_count()
                + self.pubsub.indexed_global_remaining();
        }
        unused_iter(&self.exchanges, ReplaySource::Startup).count()
            + self.pubsub.global_unused_count()
    }
}
