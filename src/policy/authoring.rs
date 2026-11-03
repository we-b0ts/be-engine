//! The unified transaction owns policy authoring; historical DTOs only recover journals.
mod api;
mod async_api;
mod contracts;
mod dependency_lifetimes;
mod document;
mod http;
mod proof;
mod recording;
mod redis_keys;
#[cfg(test)]
mod redis_tests;
mod render;
mod resources;
mod signatures;
#[cfg(test)]
mod tests;
mod walk;

pub use document::effective_rules;
pub(crate) use document::expanded;
pub use render::render_policy;
pub(crate) use walk::expand_rule;
pub(crate) use walk::require_source_proof;

/// Explicit HTTP request selectors retain their authored API scope only when
/// the complete generated native owner can be reconstructed losslessly.
pub(crate) fn preserves_http_api_scope(
    rule: &crate::policy::PolicyRule,
    resources: &std::collections::BTreeMap<String, crate::policy::ResourceDeclaration>,
) -> anyhow::Result<bool> {
    if !rule
        .as_native()
        .is_some_and(|rule| rule.selector.api.is_some())
    {
        return Ok(false);
    }
    http::compact(rule, resources, &mut serde_yaml::Mapping::new())
}

pub fn require_source_proofs(document: &crate::policy::TrafficPolicy) -> anyhow::Result<()> {
    for rule in &document.rules {
        let mut value = serde_yaml::to_value(rule)?;
        walk::require_source_proof(&mut value, document.source_revision.as_deref())?;
    }
    async_api::require(document.async_api.as_ref())?;
    Ok(())
}

pub(crate) fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v3"
    )
}
