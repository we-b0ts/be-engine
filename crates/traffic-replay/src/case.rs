//! Case progress and bounded failure observations supplied by inventory owners.
use serde::Serialize;
use serde_json::{Value, json};

pub trait CaseRuntimeProjection {
    fn case_has_runtime_failure(&self, case: &str) -> bool;
    fn append_matched_dependency_counts(&self, case: &str, counts: &mut Vec<usize>);
    fn append_case_failures(&self, case: &str, failures: &mut Vec<Value>, limit: usize);
}

pub fn append_failure_summaries<T: Serialize>(
    failures: &mut Vec<Value>,
    limit: usize,
    protocol: &str,
    kind: &str,
    entries: impl Iterator<Item = T>,
) {
    for entry in entries.take(limit.saturating_sub(failures.len())) {
        let entry = serde_json::to_value(entry).expect("Replay failure serializes");
        let mut failure = json!({"protocol":protocol,"kind":kind});
        for key in [
            "command",
            "method",
            "reason",
            "target_event_index",
            "diagnostic",
        ] {
            if let Some(value) = entry.get(key) {
                failure[key] = value.clone();
            }
        }
        failures.push(failure);
    }
}
