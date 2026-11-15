//! Stored native report formats validate their own finite session obligations.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::BTreeMap;

pub trait SessionEvidence {
    fn validate_session(&self, report: &Value) -> Result<BTreeMap<String, usize>>;
}

pub fn array<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    value[name]
        .as_array()
        .with_context(|| format!("actual Replay report lacks {name} evidence"))
}

pub fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .with_context(|| format!("actual Replay report lacks {name} count"))
}

pub fn empty(value: &Value, names: &[&str]) -> Result<()> {
    for name in names {
        ensure!(
            array(value, name)?.is_empty(),
            "actual Replay still has {name} obligations"
        );
    }
    Ok(())
}
