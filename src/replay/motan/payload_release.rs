use super::*;

impl MotanReplayState {
    pub(in crate::replay) fn release_consumed_payloads(
        &mut self,
        cases: &BTreeMap<String, crate::replay::ReplayCase>,
    ) {
        for exchange in &mut self.exchanges {
            if exchange.source == ReplaySource::Case
                && exchange.status.is_consumed()
                && exchange.case_id.as_ref().is_some_and(|id| {
                    cases
                        .get(id)
                        .is_some_and(|case| case.status == crate::replay::ReplayCaseStatus::Ended)
                })
            {
                exchange.response = Vec::new();
                exchange.record.response.data = String::new();
                exchange.record.request.data = String::new();
            }
        }
    }
}
