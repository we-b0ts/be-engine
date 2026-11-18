//! Sparse report visibility changes. Native protocol status and consumption
//! remain with their existing owners.
use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub section: u8,
    pub index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub position: Position,
    pub before: bool,
    pub after: bool,
}

#[derive(Debug, Default)]
pub struct Usage {
    layout: Vec<usize>,
    baseline: Option<usize>,
    changes: BTreeMap<Position, Change>,
    added: usize,
    removed: usize,
}

impl Usage {
    pub fn freeze_layout(&mut self, layout: Vec<usize>) {
        self.layout = layout;
    }
    pub fn layout(&self) -> &[usize] {
        &self.layout
    }
    pub fn rows<'a, T>(
        &self,
        section: usize,
        values: &'a [T],
        extras: bool,
    ) -> impl Iterator<Item = (usize, &'a T)> + 'a {
        let boundary = self.layout.get(section).copied().unwrap_or(values.len());
        let (start, end) = if extras {
            (boundary, values.len())
        } else {
            (0, boundary)
        };
        values
            .get(start..end)
            .expect("Global report layout exceeds its admitted native inventory")
            .iter()
            .enumerate()
            .map(move |(index, value)| (start + index, value))
    }
    pub fn initialize(&mut self, visible: usize) {
        self.baseline = Some(visible);
    }

    /// The baseline is immutable inventory visibility, not the previous status.
    pub fn observe(&mut self, section: u8, index: usize, baseline_visible: bool, after: bool) {
        let position = Position { section, index };
        let core = self
            .layout
            .get(section as usize)
            .is_none_or(|boundary| index < *boundary);
        let baseline_visible = if let Some(previous) = self.changes.remove(&position) {
            if core && previous.after {
                self.added -= 1;
            } else if core {
                self.removed -= 1;
            }
            previous.before
        } else {
            baseline_visible
        };
        if baseline_visible != after {
            self.changes.insert(
                position,
                Change {
                    position,
                    before: baseline_visible,
                    after,
                },
            );
            if core && after {
                self.added += 1;
            } else if core {
                self.removed += 1;
            }
        }
    }

    pub fn count(&self) -> Option<usize> {
        self.baseline?
            .checked_sub(self.removed)?
            .checked_add(self.added)
    }

    /// Query one sparse visibility change without materializing the report.
    pub fn visibility_at(&self, position: Position, baseline: bool) -> bool {
        self.changes
            .get(&position)
            .map_or(baseline, |change| change.after)
    }

    pub fn count_with(&self, other: &Self) -> Option<usize> {
        self.count()?
            .checked_sub(other.removed)?
            .checked_add(other.added)
    }

    pub fn snapshot_with(&self, other: &Self) -> Result<(usize, Vec<Change>)> {
        let count = self
            .count_with(other)
            .context("combined Global visibility underflow")?;
        let mut changes = self
            .changes
            .values()
            .chain(other.changes.values())
            .copied()
            .collect::<Vec<_>>();
        changes.sort_unstable_by_key(|change| change.position);
        Ok((count, changes))
    }

    pub fn snapshot(&self) -> Result<(usize, Vec<Change>)> {
        Ok((
            self.count()
                .context("Global report visibility was not initialized or underflowed")?,
            self.changes.values().copied().collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_completion_and_optional_failure_are_sparse_and_reversible() {
        let mut usage = Usage::default();
        usage.initialize(10);
        usage.observe(0, 4, true, false);
        usage.observe(0, 4, false, false);
        usage.observe(1, 4, false, true);
        assert_eq!(usage.count(), Some(10));
        assert_eq!(usage.snapshot().unwrap().1.len(), 2);
        usage.observe(0, 4, true, true);
        usage.observe(1, 4, false, false);
        assert_eq!(usage.count(), Some(10));
        assert!(usage.snapshot().unwrap().1.is_empty());
    }
}
