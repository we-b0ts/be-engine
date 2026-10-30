//! Only original case-owned/projected native inputs participate in compression.
use super::*;
use crate::replay::control::input_timing::{DeliveryReference, Evidence};

impl PubSubState {
    pub(in crate::replay) fn timing_evidence(
        &self,
        case: &str,
        start: chrono::DateTime<chrono::Utc>,
    ) -> (Vec<Evidence>, bool) {
        let mut entries = self.native_clock.timing_evidence(case);
        entries.extend(self.ingress.timing_evidence(case, start));
        let mut covered = true;
        for (index, push) in
            self.pushes.iter().enumerate().filter(|(_, p)| {
                p.source == ReplaySource::Case && p.case_id.as_deref() == Some(case)
            })
        {
            if let Some(at) = push.record.timestamp {
                entries.push(Evidence {
                    reference: DeliveryReference::NativePush(PushId::Inline(index)),
                    completed_at: at,
                });
            } else {
                covered = false;
            }
        }
        (entries, covered)
    }
}
