//! The unified transaction owns policy authoring; historical DTOs only recover journals.
mod contracts;
mod document;
mod proof;
mod redis_keys;
#[cfg(test)]
mod redis_tests;
mod render;
mod resources;
#[cfg(test)]
mod tests;
mod walk;

pub use document::effective_rules;
pub(crate) use document::expanded;
pub use render::render_policy;
pub(crate) use walk::expand_rule;
pub(crate) use walk::require_source_proof;

pub fn require_source_proofs(document: &crate::policy::TrafficPolicy) -> anyhow::Result<()> {
    for rule in &document.rules {
        let mut value = serde_yaml::to_value(rule)?;
        walk::require_source_proof(&mut value, document.source_revision.as_deref())?;
    }
    Ok(())
}

pub(crate) fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v2"
    )
}
