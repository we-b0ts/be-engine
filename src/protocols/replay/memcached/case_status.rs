//! Case failure observations remain distinct from unconsumed Source commands.
use super::*;
impl MemcachedReplayState {
    pub(crate) fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.events.dirty_case_ids.contains(case)
    }

    pub(crate) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
    }
}

impl traffic_replay::case::CaseRuntimeProjection for MemcachedReplayState {
    fn case_has_runtime_failure(&self, case: &str) -> bool {
        MemcachedReplayState::case_has_runtime_failure(self, case)
    }
    fn append_matched_dependency_counts(&self, case: &str, counts: &mut Vec<usize>) {
        counts.push(self.events.matched_details.next_event_index(Some(case)));
    }
    fn append_case_failures(
        &self,
        case: &str,
        failures: &mut Vec<serde_json::Value>,
        limit: usize,
    ) {
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "memcached",
            "unmatched",
            self.events
                .unmatched
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "memcached",
            "unsupported",
            self.events
                .unsupported
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "memcached",
            "unsafe_events",
            self.events
                .unsafe_events
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
    }
}
