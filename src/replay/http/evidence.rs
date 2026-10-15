//! Retain HTTP request identity and defer only the Global response body.
use super::*;
use crate::dependency_index::RecordRef;

pub(in crate::replay) fn register_global_exchange(
    record: RecordedHttpExchange,
    reference: RecordRef,
    exchanges: &mut Vec<ReplayHttpExchange>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    register_http_exchange(record, ReplaySource::Global, None, exchanges, targets)?;
    let record = &mut exchanges
        .last_mut()
        .expect("registered HTTP exchange")
        .record;
    record.response_evidence = Some(reference);
    if let Some(body) = &mut record.response_body {
        body.data = String::new();
    }
    Ok(())
}

impl RecordedHttpExchange {
    pub(super) fn materialize_response(&mut self) -> Result<()> {
        if let Some(reference) = self.response_evidence.take() {
            self.response_body = reference.load::<RecordedHttpExchange>()?.response_body;
        }
        Ok(())
    }
}

impl ReplayState {
    pub(in crate::replay) fn visit_global_http_unused(
        &self,
        visitor: &mut dyn FnMut(serde_json::Value) -> Result<()>,
    ) -> Result<()> {
        for item in self.unused_http_iter(ReplaySource::Global, false) {
            visitor(serde_json::to_value(item)?)?;
        }
        Ok(())
    }
    pub(in crate::replay) fn global_http_unused_count(&self) -> usize {
        self.unused_http_iter(ReplaySource::Global, false).count()
    }
}
