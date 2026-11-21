//! Resolve prepared execution inputs from a rewrite snapshot.
use super::model::RewriteState;
use anyhow::{Context, Result};
use std::path::Path;
use traffic_engine_e2e_contract::E2eRunContext;

pub fn e2e_context(target_root: &Path, state: &RewriteState) -> Result<E2eRunContext> {
    Ok(E2eRunContext {
        target_root: target_root.to_path_buf(),
        case_source: state
            .case_source
            .clone()
            .context("rewrite workflow has no finalized case source")?,
        run_key: None,
    })
}

pub fn case_source(target_root: &Path, state: &RewriteState) -> Result<std::path::PathBuf> {
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no finalized case source")?;
    Ok(if case_source.is_absolute() {
        case_source
    } else {
        target_root.join(case_source)
    })
}

pub fn group_id(state: &RewriteState) -> Result<&str> {
    state
        .group_id
        .as_deref()
        .context("rewrite workflow has no prepared API group")
}
