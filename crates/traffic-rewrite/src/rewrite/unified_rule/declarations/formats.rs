//! One additive format union preserves Source selection order across carriers.
use crate::policy::GlobalField;
use anyhow::{Result, ensure};

pub(super) fn merge(existing: &mut GlobalField, proposed: &GlobalField) -> Result<()> {
    match (existing, proposed) {
        (GlobalField::Time { formats: before }, GlobalField::Time { formats: after }) => {
            append(before, after)
        }
        (GlobalField::Identity { formats: before }, GlobalField::Identity { formats: after }) => {
            append(before, after)
        }
        (GlobalField::Duration { formats: before }, GlobalField::Duration { formats: after }) => {
            append(before, after)
        }
        (GlobalField::Url { formats: before }, GlobalField::Url { formats: after }) => {
            append(before, after)
        }
        (GlobalField::Template { formats: before }, GlobalField::Template { formats: after }) => {
            append(before, after)
        }
        (before, after) => ensure!(
            before == after,
            "existing field kind or non-format contract cannot be changed by an additive proposal"
        ),
    }
    Ok(())
}

fn append<T: Clone + PartialEq>(before: &mut Vec<T>, after: &[T]) {
    let mut merged = Vec::with_capacity(before.len() + after.len());
    for format in before.iter().chain(after) {
        if !merged.contains(format) {
            merged.push(format.clone());
        }
    }
    *before = merged;
}
