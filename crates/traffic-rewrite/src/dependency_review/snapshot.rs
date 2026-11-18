//! Coordinator snapshot adapter for the independent attribution library.
#[cfg(test)]
use crate::dependency::attribution::AttributionDecision;
use crate::dependency::attribution::DependencyOwner;
use crate::{model::RewriteState, store::RewriteStore};
use anyhow::Result;
use std::{collections::BTreeMap, path::Path};
pub(super) fn read_snapshot(root: &Path) -> Result<Option<RewriteState>> {
    RewriteStore::new(root)?.load_snapshot()
}
pub(crate) fn identity(root: &Path, run: &str) -> Result<String> {
    traffic_rewrite_attribution::snapshot::identity(read_snapshot, root, run)
}
pub(crate) fn identity_for_source(root: &Path, source: &Path, run: &str) -> Result<String> {
    traffic_rewrite_attribution::snapshot::identity_for_source(read_snapshot, root, source, run)
}
#[cfg(test)]
pub(crate) fn overlay(root: &Path, run: &str) -> Result<Vec<AttributionDecision>> {
    traffic_rewrite_attribution::snapshot::overlay(read_snapshot, root, run)
}
pub(crate) fn frozen(
    target: Option<&Path>,
    source: &Path,
    run: &str,
) -> Result<(BTreeMap<uuid::Uuid, DependencyOwner>, String)> {
    traffic_rewrite_attribution::snapshot::frozen(read_snapshot, target, source, run)
}
