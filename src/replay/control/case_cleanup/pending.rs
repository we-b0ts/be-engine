//! Capture actual cleanup blockers while the Case ownership lock is still held.
use super::*;
use serde_json::{Value, json};

const MAX_REFERENCES: usize = 4;

pub(super) fn snapshot(state: &ReplayState) -> Value {
    let mysql = state.mysql.exchanges.iter().enumerate().filter(|(_, e)| {
        e.source == ReplaySource::Case
            && matches!(
                e.status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
    });
    let mysql_count = mysql.clone().count();
    let mysql_references = mysql
        .take(MAX_REFERENCES)
        .map(|(index, e)| {
            json!({"index":index, "case_id":e.case_id,
            "connection_id":e.record.connection_id, "query_sequence":e.record.query_sequence,
            "status":format!("{:?}", e.status)})
        })
        .collect::<Vec<_>>();
    json!({
        "mysql":{"count":mysql_count, "references":mysql_references,
            "omitted":mysql_count.saturating_sub(MAX_REFERENCES)},
        "redis":state.redis.case_in_flight_diagnostic(),
        "http":state.http_case_in_flight_diagnostic(),
        "kafka":state.kafka.has_case_in_flight(),
        "connect_failures":state.connect_failures.has_in_flight(),
        "memcached":state.memcached.has_case_in_flight(),
        "motan":state.motan.has_case_in_flight(),
    })
}
