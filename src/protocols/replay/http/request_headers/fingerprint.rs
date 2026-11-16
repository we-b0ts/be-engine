//! Application wrapper for native immutable HTTP evidence identity.
use super::*;
pub(crate) fn recorded_fingerprint(record: &RecordedHttpExchange) -> String {
    traffic_protocol_http::request_contract::recorded_header_fingerprint(&record.native)
}
