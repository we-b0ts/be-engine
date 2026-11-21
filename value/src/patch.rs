//! Shared authorization of logical leaf edits before a codec renders bytes.
use anyhow::{Result, ensure};

use crate::{Value, path};

pub fn validate_patch(before: &Value, after: &Value, allowed: &[String]) -> Result<()> {
    validate(before, after, "", allowed)
}

fn validate(before: &Value, after: &Value, pointer: &str, allowed: &[String]) -> Result<()> {
    if before == after {
        return Ok(());
    }
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            ensure!(
                before.keys().eq(after.keys()),
                "delivery changes field presence at {pointer:?}"
            );
            for (key, value) in before {
                validate(
                    value,
                    &after[key],
                    &format!("{pointer}/{}", path::escape(key)),
                    allowed,
                )?;
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            ensure!(
                before.len() == after.len(),
                "delivery changes array cardinality at {pointer:?}"
            );
            for (index, (before, after)) in before.iter().zip(after).enumerate() {
                validate(before, after, &format!("{pointer}/{index}"), allowed)?;
            }
        }
        _ => {
            ensure!(
                std::mem::discriminant(before) == std::mem::discriminant(after)
                    && !matches!(before, Value::Array(_) | Value::Object(_)),
                "delivery changes scalar type or structure at {pointer:?}"
            );
            if let (Value::Number(before), Value::Number(after)) = (before, after) {
                ensure!(
                    std::mem::discriminant(before) == std::mem::discriminant(after),
                    "delivery changes numeric category at {pointer:?}"
                );
            }
            ensure!(
                allowed
                    .iter()
                    .any(|pattern| path::matches(pattern, pointer)),
                "delivery changes an unauthorized field at {pointer:?}"
            );
        }
    }
    Ok(())
}
