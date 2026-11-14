use super::*;
pub(in crate::replay) fn active_case_matches(
    active_case_id: Option<&str>,
    exchange: &ReplayExchange,
) -> bool {
    match exchange.source {
        ReplaySource::Startup | ReplaySource::Process => true,
        ReplaySource::Case => exchange.case_id.as_deref() == active_case_id,
        ReplaySource::Unattributed => false,
    }
}
