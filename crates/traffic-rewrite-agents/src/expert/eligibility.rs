//! Expert assistance eligibility bound to accepted worker observations.
use super::model::RewriteExpertState;
use chrono::{DateTime, Duration, Utc};
const EXPERT_AFTER_SECONDS: i64 = 2 * 60 * 60;

pub fn eligible_after(
    binding: &traffic_rewrite_model::rewrite::worker::model::RewriteWorkerBinding,
) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(
        binding
            .last_integrated_at
            .as_deref()
            .or(binding.first_bound_at.as_deref())?,
    )
    .ok()?
    .with_timezone(&Utc)
    .checked_add_signed(Duration::seconds(EXPERT_AFTER_SECONDS))
}

pub fn state_at(
    binding: &traffic_rewrite_model::rewrite::worker::model::RewriteWorkerBinding,
    now: DateTime<Utc>,
) -> RewriteExpertState {
    match &binding.expert {
        Some(expert) if expert.closed_at.is_some() => RewriteExpertState::Closed,
        Some(expert) if expert.delivery.is_some() => RewriteExpertState::Delivered,
        Some(expert) if expert.agent_handle_fingerprint.is_some() => RewriteExpertState::Confirmed,
        Some(_) => RewriteExpertState::DispatchRequired,
        None => match eligible_after(binding) {
            None => RewriteExpertState::NotDue,
            Some(after) if now > after => RewriteExpertState::PrepareRequired,
            Some(_) => RewriteExpertState::NotDue,
        },
    }
}
