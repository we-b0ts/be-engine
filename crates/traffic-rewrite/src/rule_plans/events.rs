//! Bind rule plan publication to the coordinator's overlay-aware snapshot.
use std::path::Path;

use anyhow::Result;
use traffic_rewrite_rules::rewrite::plan_journal;
pub(crate) use traffic_rewrite_rules::rewrite::plan_journal::{
    compact, ensure_not_replaying, lock, lock_api, overlay,
};

use crate::{
    model::{RewriteRulePlanRecord, RewriteState},
    store::RewriteStore,
};

pub(crate) fn publish(
    target: &Path,
    expected: &RewriteState,
    plan: RewriteRulePlanRecord,
) -> Result<()> {
    plan_journal::publish(target, expected, plan, |root| {
        RewriteStore::new(root)?.load()
    })
}
