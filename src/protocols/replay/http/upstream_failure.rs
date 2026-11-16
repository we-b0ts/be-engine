//! Replay the exact 502 response produced by the recording HTTP proxy.
use super::*;

pub(super) fn is_recorded(record: &RecordedHttpExchange) -> bool {
    record.native.is_proxy_failure()
}

pub(super) fn materialize(record: &mut RecordedHttpExchange) {
    record.native.materialize_proxy_failure();
    record.materialized_proxy_failure = true;
}

#[cfg(test)]
mod tests;
