//! The unified transaction owns policy authoring; historical DTOs only recover journals.
pub mod api;
pub mod contracts;
pub mod dependency_lifetimes;
pub mod document;
pub mod http;
pub mod proof;
pub mod recording;
pub mod redis_keys;
pub mod render;
pub mod resources;
pub mod signatures;
pub mod walk;

pub use document::effective_rules;
pub use document::expanded;
pub use render::render_policy;
pub use walk::expand_rule;
pub use walk::require_source_proof;

/// Explicit HTTP request selectors retain their authored API scope only when
/// the complete generated native owner can be reconstructed losslessly.
pub fn preserves_http_api_scope(
    rule: &crate::PolicyRule,
    resources: &std::collections::BTreeMap<String, crate::ResourceDeclaration>,
    context: &crate::AuthoringContext<'_>,
) -> anyhow::Result<bool> {
    if !rule
        .as_native()
        .is_some_and(|rule| rule.selector.api.is_some())
    {
        return Ok(false);
    }
    http::compact(rule, resources, &mut serde_yaml::Mapping::new(), context)
}

pub fn require_source_proofs(document: &crate::TrafficPolicy) -> anyhow::Result<()> {
    for rule in &document.rules {
        let mut value = serde_yaml::to_value(rule)?;
        walk::require_source_proof(&mut value, document.source_revision.as_deref())?;
    }
    Ok(())
}

pub fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v3"
    )
}
