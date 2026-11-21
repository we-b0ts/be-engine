//! Render scalar edits and explicitly authorized structural transformations.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, de::Visitor};
use serde_json::{Value, value::RawValue};

/// Permissions remain with the caller. This renderer preserves field presence,
/// scalar types, array order, and every byte outside the changed scalar tokens.
pub fn derived(original: &[u8], logical: &Value) -> Result<Vec<u8>> {
    render(original, logical, false)
}

pub fn transformed(original: &[u8], logical: &Value) -> Result<Vec<u8>> {
    render(original, logical, true)
}

fn render(original: &[u8], logical: &Value, allow_structure: bool) -> Result<Vec<u8>> {
    let before = super::parse(original).context("derived input requires bounded strict JSON")?;
    if &before == logical {
        return Ok(original.to_vec());
    }
    let raw: &RawValue = serde_json::from_slice(original)?;
    let mut edits = Vec::new();
    collect(raw, &before, logical, allow_structure, &mut edits)?;
    let mut output = Vec::with_capacity(original.len());
    let mut end = 0;
    for (raw, replacement) in edits {
        let start = (raw.as_ptr() as usize)
            .checked_sub(original.as_ptr() as usize)
            .context("derived JSON token precedes its carrier")?;
        ensure!(start >= end, "derived JSON tokens overlap");
        let tail = start
            .checked_add(raw.len())
            .context("JSON token overflow")?;
        ensure!(
            tail <= original.len(),
            "derived JSON token leaves its carrier"
        );
        output.extend_from_slice(&original[end..start]);
        output.extend_from_slice(&serde_json::to_vec(replacement)?);
        end = tail;
    }
    output.extend_from_slice(&original[end..]);
    ensure!(
        output.len() <= crate::MAX_VALUE_BYTES,
        "derived JSON exceeds 64 MiB"
    );
    Ok(output)
}

fn collect<'a, 'b>(
    raw: &'a RawValue,
    before: &Value,
    after: &'b Value,
    allow_structure: bool,
    edits: &mut Vec<(&'a str, &'b Value)>,
) -> Result<()> {
    if before == after {
        return Ok(());
    }
    if allow_structure {
        let same_shape = match (before, after) {
            (Value::Object(before), Value::Object(after)) => before.keys().eq(after.keys()),
            (Value::Array(before), Value::Array(after)) => before.len() == after.len(),
            _ => std::mem::discriminant(before) == std::mem::discriminant(after),
        };
        if !same_shape {
            edits.push((raw.get(), after));
            return Ok(());
        }
    }
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            ensure!(
                before.keys().eq(after.keys()),
                "derived JSON changes object members"
            );
            let members: Members<'_> = serde_json::from_str(raw.get())?;
            for (key, value) in members.0 {
                collect(value, &before[&key], &after[&key], allow_structure, edits)?;
            }
        }
        (Value::Array(before), Value::Array(after)) => {
            ensure!(
                before.len() == after.len(),
                "derived JSON changes array cardinality"
            );
            let values: Vec<&RawValue> = serde_json::from_str(raw.get())?;
            for ((raw, before), after) in values.into_iter().zip(before).zip(after) {
                collect(raw, before, after, allow_structure, edits)?;
            }
        }
        _ => {
            let same_type = matches!(
                (before, after),
                (Value::Null, Value::Null)
                    | (Value::Bool(_), Value::Bool(_))
                    | (Value::String(_), Value::String(_))
                    | (Value::Number(_), Value::Number(_))
            );
            ensure!(same_type, "derived JSON changes scalar type or structure");
            edits.push((raw.get(), after));
        }
    }
    Ok(())
}

/// A logical map is intentionally unordered; physical member traversal is not.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Members<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

#[cfg(test)]
mod tests;
