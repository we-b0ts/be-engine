//! Whole-Source receipt validation with the coordinator's snapshot overlays.
use crate::model::RewriteState;
use anyhow::Result;
use std::path::Path;

pub(super) use traffic_rewrite_attribution::batch_verification::{
    accept, required_methods, verify,
};

pub(crate) fn current(root: &Path, state: &RewriteState) -> Result<bool> {
    traffic_rewrite_attribution::batch_verification::current(
        root,
        state,
        super::snapshot::read_snapshot,
    )
}
