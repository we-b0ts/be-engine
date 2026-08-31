use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use super::model::RewriteState;
use super::transition;
use crate::E2eRunContext;
use crate::e2e_run::{
    FocusedBackgroundReclassification, reclassify_focused_background_dependencies,
};

pub(super) fn apply(target_root: &Path, state: &mut RewriteState) -> Result<Value> {
    let case_source = state
        .case_source
        .clone()
        .context("rewrite workflow has no case source to reclassify")?;
    let api = state
        .group_id
        .clone()
        .context("rewrite workflow has no focused API to reclassify")?;
    let reclassification: FocusedBackgroundReclassification =
        reclassify_focused_background_dependencies(
            E2eRunContext {
                target_root: target_root.to_path_buf(),
                case_source,
                run_key: None,
            },
            &api,
        )?;
    transition::from_e2e_result(
        target_root,
        state,
        &reclassification.result,
        transition::AttemptTransition::ReclassifyCurrent,
    )?;
    Ok(serde_json::to_value(reclassification)?)
}
