//! Ordinary Case evidence cannot establish or invalidate another Case's proof.
use super::{RecordedExchange, ReplayExchange, ReplaySource};

pub(super) fn is_other_ordinary_case(
    owner: &str,
    source: ReplaySource,
    case: Option<&str>,
    record: &RecordedExchange,
) -> bool {
    source == ReplaySource::Case
        && case.is_some_and(|case| case != owner)
        && record.cache_snapshot_rule.is_none()
        && !record.cache_snapshot_hit
        && record.global_dependency_reason.is_none()
        && !record.session_setup
}

pub(super) fn is_other_ordinary_exchange(owner: &str, exchange: &ReplayExchange) -> bool {
    exchange.shared_rule_id.is_none()
        && !exchange.reusable_snapshot
        && is_other_ordinary_case(
            owner,
            exchange.source,
            exchange.case_id.as_deref(),
            &exchange.record,
        )
}
