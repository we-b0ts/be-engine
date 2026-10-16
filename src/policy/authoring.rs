//! The unified transaction owns policy authoring; historical DTOs only recover journals.
pub(crate) fn retired_authoring() -> anyhow::Result<()> {
    anyhow::bail!(
        "legacy rule authoring is retired; use backend-rewrite rule plan/apply with traffic-policy/v1"
    )
}
