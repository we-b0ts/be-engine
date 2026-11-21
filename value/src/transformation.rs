//! Authorize explicit logical transformations and project their changed locations.
use anyhow::{Result, ensure};

use crate::{Value, path};

pub fn transformation_paths(
    before: &Value,
    after: &Value,
    selected: &[String],
) -> Result<Vec<String>> {
    let mut changed = Vec::new();
    visit(before, after, "", false, selected, &mut changed)?;
    Ok(changed)
}

fn visit(
    before: &Value,
    after: &Value,
    pointer: &str,
    ancestor_selected: bool,
    selected: &[String],
    changed: &mut Vec<String>,
) -> Result<()> {
    if before == after {
        return Ok(());
    }
    let permitted = ancestor_selected || selected.iter().any(|path| path::matches(path, pointer));
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            for (key, value) in before {
                let child = format!("{pointer}/{}", path::escape(key));
                match after.get(key) {
                    Some(after) => visit(value, after, &child, permitted, selected, changed)?,
                    None => record_change(&child, permitted, selected, changed)?,
                }
            }
            for key in after.keys().filter(|key| !before.contains_key(*key)) {
                record_change(
                    &format!("{pointer}/{}", path::escape(key)),
                    permitted,
                    selected,
                    changed,
                )?;
            }
        }
        (Value::Array(before), Value::Array(after)) if before.len() == after.len() => {
            for (index, (before, after)) in before.iter().zip(after).enumerate() {
                visit(
                    before,
                    after,
                    &format!("{pointer}/{index}"),
                    permitted,
                    selected,
                    changed,
                )?;
            }
        }
        _ => {
            record_change(pointer, permitted, selected, changed)?;
        }
    }
    Ok(())
}

fn record_change(
    pointer: &str,
    ancestor_selected: bool,
    selected: &[String],
    changed: &mut Vec<String>,
) -> Result<()> {
    ensure!(
        ancestor_selected || selected.iter().any(|path| path::matches(path, pointer)),
        "transformation changes an unauthorized field at {pointer:?}"
    );
    changed.push(pointer.into());
    Ok(())
}
