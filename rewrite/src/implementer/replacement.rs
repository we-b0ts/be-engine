//! Replace a missing runtime session without discarding its fixed slot or pending APIs.
use anyhow::{Context, Result};
use traffic_rewrite_agents::implementer::replacement;

use super::model::ImplementerReplaceRuntimeOptions;
use crate::{model::RewriteActionEnvelope, review, store::RewriteStore, worker};

pub fn replace_runtime(options: ImplementerReplaceRuntimeOptions) -> Result<RewriteActionEnvelope> {
    crate::purpose::require_work_branch(&options.target_root)?;
    replacement::validate(&options)?;
    let (root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&root)?;
    let lock = worker::events::lock(&root)?;
    let mut state = store
        .load()?
        .context("rewrite workflow is not initialized")?;
    let scopes = worker::runtime::scopes(&state);
    if let Some(changed) = replacement::apply(&root, &mut state, options, &scopes, review::bind)? {
        worker::events::publish_many(&root, &state, &changed)?;
    }
    drop(lock);
    worker::runtime::current_envelope(&root)
}
