//! Application projection of shared URL value formats.
pub use traffic_policy_value::formats::url::{Document, selected};

pub fn query_plan(plan: &crate::policy::CompiledJsonPolicy) -> crate::policy::CompiledJsonPolicy {
    crate::policy::CompiledJsonPolicy {
        fields: traffic_policy_value::formats::url::query_fields(plan),
        ..plan.clone()
    }
}

#[cfg(test)]
mod tests;
