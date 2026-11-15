//! Native Case failure and delivery-progress projection.
use super::*;

impl traffic_replay::case::CaseRuntimeProjection for MysqlReplayState {
    fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.events.dirty_case_ids.contains(case)
    }
    fn append_matched_dependency_counts(&self, case: &str, counts: &mut Vec<usize>) {
        counts.push(
            self.events
                .matched_query_details
                .next_event_index(Some(case)),
        );
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
            "mysql",
            "unmatched_queries",
            self.events
                .unmatched_queries
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
        traffic_replay::case::append_failure_summaries(
            failures,
            limit,
            "mysql",
            "unsupported_commands",
            self.events
                .unsupported_commands
                .iter()
                .filter(|entry| entry.case_id.as_deref() == Some(case)),
        );
    }
}
