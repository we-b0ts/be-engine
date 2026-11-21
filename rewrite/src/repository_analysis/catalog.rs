pub(super) use traffic_rewrite_agents::analyst::catalog::*;

#[cfg(test)]
pub(super) fn path(root: &std::path::Path) -> std::path::PathBuf {
    root.join(CATALOG_PATH)
}

#[cfg(test)]
pub(super) fn publish(
    root: &std::path::Path,
    expected: &str,
    document: &super::model::CatalogDocument,
) -> anyhow::Result<()> {
    publish_encoded(root, expected, &encode(document)?)
}
