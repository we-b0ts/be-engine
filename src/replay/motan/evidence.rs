//! Global response frames use the same immutable evidence cache as other protocols.
use super::*;
use crate::dependency_index::RecordRef;

impl MotanReplayState {
    pub(crate) fn register_global_exchange(
        &mut self,
        record: RecordedExchange,
        source_kind: ReplaySource,
        reference: RecordRef,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        let before = self.exchanges.len();
        self.register_exchange(record, source_kind, None, targets)?;
        if self.exchanges.len() != before {
            let exchange = self
                .exchanges
                .last_mut()
                .expect("registered Motan exchange");
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
            Some(reference) if self.timing.outcome() == DependencyExchangeOutcome::Response => {
                reference.load::<RecordedExchange>()?.response.decode()
            }
            Some(_) => Ok(Vec::new()),
            None => Ok(self.response.clone()),
        }
    }
}

impl MotanReplayState {
    pub(in crate::replay) fn visit_global_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in unused_iter(&self.exchanges, ReplaySource::Startup) {
            visitor(serde_json::to_value(item)?)?;
        }

        Ok(())
    }
    pub(in crate::replay) fn global_unused_count(&self) -> usize {
        if let Some(count) = self.global_report_usage().count() {
            return count + self.global_report_extra_count();
        }
        unused_iter(&self.exchanges, ReplaySource::Startup).count()
    }
}
