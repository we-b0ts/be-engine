//! Native Case failure and delivery-progress projection.
use super::*;

impl traffic_replay::case::CaseRuntimeProjection for KafkaReplayState {
    fn case_has_runtime_failure(&self, case: &str) -> bool {
        KafkaReplayState::case_has_runtime_failure(self, case)
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
            "kafka",
            "unmatched",
            self.events
                .unmatched
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "kafka",
            "unsupported",
            self.events
                .unsupported
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "kafka",
            "unsafe_events",
            self.events
                .unsafe_events
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
    }
}
