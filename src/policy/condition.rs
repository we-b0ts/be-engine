//! Source sibling predicates shared by value fields and native identity captures.
use super::{FieldCondition, SourceScalar};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

#[cfg(test)]
mod tests;

impl FieldCondition {
    pub fn peer_pointer(&self, field: &str) -> Option<String> {
        let relative = self.relative_pointer.strip_prefix("..")?;
        let (parent, _) = field.rsplit_once('/')?;
        Some(format!("{parent}{relative}"))
    }

    pub(crate) fn validate(&self, field: &str) -> Result<()> {
        ensure!(
            self.relative_pointer.starts_with("../") && !self.relative_pointer.contains('*'),
            "field condition requires one exact sibling pointer such as ../status"
        );
        super::compiler::validate_pointer(&self.relative_pointer[2..], false)?;
        ensure!(
            self.relative_pointer[3..]
                .split('/')
                .all(|s| !matches!(s, "." | "..")),
            "field condition cannot escape its sibling scope"
        );
        ensure!(
            !field.is_empty() && self.peer_pointer(field).as_deref() != Some(field),
            "field condition requires a distinct sibling of a non-root field"
        );
        ensure!(
            (self.equals.is_some() && self.not_in.is_empty())
                || (self.equals.is_none() && (1..=32).contains(&self.not_in.len())),
            "field condition requires equals or 1..32 excluded scalars"
        );
        let values = self.values().collect::<Vec<_>>();
        ensure!(
            values
                .iter()
                .all(|v| std::mem::discriminant(*v) == std::mem::discriminant(values[0])),
            "field condition constants must have the same scalar type"
        );
        ensure!(
            values
                .iter()
                .all(|v| !matches!(v, SourceScalar::String(s) if s.len() > 1024)),
            "field condition string exceeds 1024 bytes"
        );
        Ok(())
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &SourceScalar> {
        self.equals.iter().chain(&self.not_in)
    }

    pub(crate) fn active(&self, root: &Value, field: &str) -> Result<bool> {
        let pointer = self
            .peer_pointer(field)
            .context("field condition requires a parent scope")?;
        let value = root
            .pointer(&pointer)
            .context("Source condition sibling is absent")?;
        if let Some(expected) = &self.equals {
            return equal(expected, value);
        }
        let mut active = true;
        for expected in &self.not_in {
            active &= !equal(expected, value)?;
        }
        Ok(active)
    }

    pub(crate) fn matches_pair(
        &self,
        source: &Value,
        target: &Value,
        source_field: &str,
        target_field: &str,
    ) -> Result<bool> {
        let left = self
            .peer_pointer(source_field)
            .context("Source condition has no sibling scope")?;
        let right = self
            .peer_pointer(target_field)
            .context("Target condition has no sibling scope")?;
        ensure!(
            source.pointer(&left).is_some() && source.pointer(&left) == target.pointer(&right),
            "field condition discriminator changed or is absent"
        );
        self.active(source, source_field)
    }

    pub(crate) fn disjoint(&self, other: &Self) -> bool {
        match (&self.equals, &other.equals) {
            (Some(a), Some(b)) => a != b,
            (Some(a), None) => other.not_in.contains(a),
            (None, Some(b)) => self.not_in.contains(b),
            (None, None) => false,
        }
    }
}

fn equal(expected: &SourceScalar, value: &Value) -> Result<bool> {
    Ok(match (expected, value) {
        (SourceScalar::Bool(a), Value::Bool(b)) => a == b,
        (SourceScalar::String(a), Value::String(b)) => a == b,
        (SourceScalar::Number(a), Value::Number(b)) => {
            ensure!(
                a.is_i64() == b.is_i64() && a.is_u64() == b.is_u64(),
                "Source condition sibling numeric type differs"
            );
            a == b
        }
        _ => anyhow::bail!("Source condition sibling type differs"),
    })
}
