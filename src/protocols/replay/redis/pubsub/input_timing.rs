//! Only original case-owned/projected native inputs participate in compression.
use super::*;
use crate::replay::control::input_timing::Evidence;

impl PubSubState {
    pub(crate) fn timing_evidence(
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
                    reference: PushId::Inline(index).timing_reference(),
                    completed_at: at,
                    individual: true,
                });
            } else {
                covered = false;
            }
        }
        (entries, covered)
    }
}
