//! Timestamp-owned relationship state is transactional through the host observation port.
use std::{any::Any, collections::BTreeMap};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use traffic_policy::{ObservationState, ScopeKey};

const MAX_OBSERVATIONS: usize = 4096;
type Group = (String, Option<String>, ScopeKey);

#[derive(Clone, Default)]
pub(super) struct TimestampObservations {
    groups: BTreeMap<Group, Vec<(i128, i128)>>,
    scoped_count: usize,
}

impl TimestampObservations {
    pub(super) fn one(
        clock: String,
        group: Option<String>,
        scope: ScopeKey,
        pair: (i128, i128),
    ) -> Self {
        let scoped_count = usize::from(!scope.is_shared());
        Self {
            groups: BTreeMap::from([((clock, group, scope), vec![pair])]),
            scoped_count,
        }
    }

    fn insert(&mut self, group: &Group, pair: (i128, i128)) -> Result<()> {
        let existing = self.groups.get(group);
        if existing.is_some_and(|pairs| pairs.contains(&pair)) {
            return Ok(());
        }
        let count = if group.2.is_shared() {
            existing.map_or(0, Vec::len)
        } else {
            self.scoped_count
        };
        ensure!(
            count < MAX_OBSERVATIONS,
            "time relationship exceeds 4096 distinct observations"
        );
        for other in existing.into_iter().flatten() {
            traffic_time::validate_relationships(&[*other, pair])?;
        }
        self.groups.entry(group.clone()).or_default().push(pair);
        self.scoped_count += usize::from(!group.2.is_shared());
        Ok(())
    }
}

pub(super) fn is_implicit(group: Option<&str>) -> bool {
    group.is_some_and(|group| {
        traffic_time::declaration::is_schema_clock_group(
            group.split(".occurrence.").next().unwrap_or(group),
        )
    })
}

impl ObservationState for TimestampObservations {
    fn clone_state(&self) -> Box<dyn ObservationState> {
        Box::new(self.clone())
    }

    fn merge(&mut self, other: &dyn ObservationState) -> Result<()> {
        let other = other
            .as_any()
            .downcast_ref::<Self>()
            .context("timestamp observation implementation changed")?;
        for (group, pairs) in &other.groups {
            for pair in pairs {
                self.insert(group, *pair)?;
            }
        }
        Ok(())
    }

    fn scope(&mut self, context: &str) {
        let digest = Sha256::digest(context.as_bytes());
        self.groups = std::mem::take(&mut self.groups)
            .into_iter()
            .map(|((clock, group, scope), pairs)| {
                let group = group.map(|group| {
                    if is_implicit(Some(&group)) {
                        format!("{group}.occurrence.{digest:x}")
                    } else {
                        group
                    }
                });
                ((clock, group, scope), pairs)
            })
            .collect();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests;
