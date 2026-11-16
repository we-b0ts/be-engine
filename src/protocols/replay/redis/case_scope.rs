//! Apply native storage isolation to the framework's Case and sharing facts.
use super::{RecordedExchange, ReplaySource};
pub(super) fn is_other_ordinary_case(
    owner: &str,
    source: ReplaySource,
    case: Option<&str>,
    record: &RecordedExchange,
) -> bool {
    traffic_protocol_redis::storage::is_other_ordinary_case(owner, source, case, &record.native)
}
