use crate::action;
use crate::model::RewriteState;
use crate::request_rules::policy;
use anyhow::Result;
use serde_json::{Value, json};
use std::path::Path;
mod discovery;
pub fn signing_key_discovery(root: &Path) -> Value {
    discovery::query(root)
}

pub fn evidence_facts(root: &Path, state: &RewriteState) -> Result<Value> {
    let mut result = serde_json::to_value(facts(root, state)?)?;
    result["signing_key_discovery"] = signing_key_discovery(root);
    Ok(result)
}

pub use traffic_rewrite_rules::rewrite::jwt_plan::facts;
