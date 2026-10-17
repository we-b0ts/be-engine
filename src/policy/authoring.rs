//! The unified transaction owns policy authoring; historical DTOs only recover journals.
mod contracts;
mod document;
mod proof;
mod render;
#[cfg(test)]
mod tests;
mod walk;

pub(crate) use document::expanded;
pub use render::render_policy;
pub(crate) use walk::expand_rule;

pub(crate) fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v1"
    )
}
