//! Preserve command metadata while deferring Global response frames.
use super::*;
use crate::dependency_index::RecordRef;

impl MemcachedReplayState {
    pub(crate) fn register_global_exchange(
        &mut self,
        record: RecordedExchange,
        source_kind: ReplaySource,
        reference: RecordRef,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        self.register_exchange(record, source_kind, None, targets)?;
        let exchange = self
            .exchanges
            .last_mut()
            .expect("registered Memcached exchange");
        exchange.response_evidence = Some(reference);
        exchange.response_frames = Vec::new();
        exchange.record.response_frames = Vec::new();
        Ok(())
    }
}

impl ReplayExchange {
    pub(super) fn response_bytes(&self) -> Result<Vec<Vec<u8>>> {
        match &self.response_evidence {
            Some(reference) => reference
                .load::<RecordedExchange>()?
                .response_frames
                .iter()
                .map(RecordedCapture::decode)
                .collect(),
            None => Ok(self.response_frames.clone()),
        }
    }
}

impl MemcachedReplayState {
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
