//! Application projection of shared URL value formats.
pub use traffic_policy_value::formats::url::{Document, selected};

pub fn query_plan(plan: &crate::policy::CompiledJsonPolicy) -> crate::policy::CompiledJsonPolicy {
    plan.with_fields(traffic_policy_value::formats::url::query_fields(plan))
}

#[cfg(test)]
mod tests;
