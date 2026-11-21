//! Native report adapters validate their persisted obligations.
use anyhow::{Context, Result, ensure};
use serde_json::Value;

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

/// A historical named section has no obligation when that layout is absent.
pub fn named_section(report: &Value, protocol: &str) -> Result<Option<usize>> {
    let Some(section) = report.get(protocol) else {
        return Ok(None);
    };
    empty(
        section,
        &[
            "unmatched",
            "unsupported",
            "unsafe_events",
            "unused_case",
            "unused_global",
        ],
    )?;
    let count = match section.get("unused_global_count") {
        Some(_) => number(section, "unused_global_count")?,
        None => 0,
    };
    Ok(Some(usize::try_from(count)?))
}
