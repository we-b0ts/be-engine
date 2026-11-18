//! Bind final receipt verification to the coordinator's review and snapshot readers.
use crate::model::RewriteState;
use anyhow::Result;
use std::path::Path;
use traffic_rewrite_attribution::workflow_verification as verification;
pub(crate) use verification::pending;
pub(super) use verification::{methods, required_scope_methods};

pub(crate) fn current(root: &Path, state: &RewriteState) -> Result<bool> {
    verification::current(root, state, super::snapshot::read_snapshot)
}

pub(super) fn accept(root: &Path, state: &mut RewriteState) -> Result<Vec<String>> {
    verification::accept(
        root,
        state,
        super::snapshot::read_snapshot,
        crate::review::pre_revalidation::completion_current,
    )
}

#[cfg(test)]
mod tests;
