//! Application projection of shared URL value formats.
pub(crate) use traffic_policy_value::formats::url::{Document, selected};

pub(crate) fn query_plan(
    plan: &crate::policy::CompiledJsonPolicy,
) -> crate::policy::CompiledJsonPolicy {
    crate::policy::CompiledJsonPolicy {
        fields: traffic_policy_value::formats::url::query_fields(plan),
        ..plan.clone()
    }
}

#[cfg(test)]
mod tests;
