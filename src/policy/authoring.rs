//! The unified transaction owns policy authoring; historical DTOs only recover journals.
mod contracts;
mod document;
mod field_refs;
mod proof;
mod render;
mod resources;
#[cfg(test)]
mod tests;
mod walk;

pub(crate) use document::expanded;
pub use render::render_policy;
pub(crate) use walk::expand_rule;

pub(super) fn transform_field(value: &mut serde_yaml::Value, compact: bool) -> anyhow::Result<()> {
    transform_field_at(value, compact, 0)
}

fn transform_field_at(
    value: &mut serde_yaml::Value,
    compact: bool,
    depth: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(depth < 128, "field contract nesting exceeds 128 levels");
    contracts::transform(value, true, compact)?;
    if let Some(child) = value.get_mut("contract") {
        transform_field_at(child, compact, depth + 1)?;
    }
    Ok(())
}

pub(super) fn resolve_declaration_proof(
    value: serde_yaml::Value,
    revision: Option<&str>,
) -> anyhow::Result<serde_yaml::Value> {
    proof::expand(Some(value), None, revision)
}

pub(crate) fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v2"
    )
}
