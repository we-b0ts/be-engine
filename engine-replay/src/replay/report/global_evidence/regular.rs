//! Shared native Global summaries and sparse session visibility. Case overlays
//! are projected separately by the enclosing report reader.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::artifact::ArtifactReference;
pub use super::regular_store::Row;
use super::regular_store::{Builder, Identity, Inventory};
#[cfg(test)]
use super::regular_usage::Usage;
use super::regular_usage::{Change, Position};
mod cursor;

#[cfg(test)]
#[path = "regular_tests.rs"]
pub mod tests;

#[derive(Debug)]
pub struct RegularBaseline {
    reference: ArtifactReference,
    origin_report: PathBuf,
    pub visible: usize,
    extras: Vec<Row>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularEvidence {
    inventory: ArtifactReference,
    recorded: usize,
    baseline_visible: usize,
    remaining: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extras: Vec<Row>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    changes: Vec<Change>,
}

impl RegularBaseline {
    #[cfg(test)]
    fn retain(
        report: &Path,
        identity: Identity,
        visit: impl FnOnce(&mut dyn FnMut(Row) -> Result<()>) -> Result<()>,
    ) -> Result<Self> {
        Self::retain_from_source(report, identity, None, visit)
    }
    pub fn retain_from_source(
        report: &Path,
        identity: Identity,
        source: Option<&Path>,
        visit: impl FnOnce(&mut dyn FnMut(Row) -> Result<()>) -> Result<()>,
    ) -> Result<Self> {
        let reference = retain_reference(report, identity.clone(), false, source, visit)?;
        let (inventory, _) = reference.load::<Inventory>(report)?;
        inventory.validate(&reference)?;
        ensure!(
            inventory.identity == identity,
            "Global projection Source or policy identity changed"
        );
        Ok(Self {
            reference,
            origin_report: report.to_owned(),
            visible: inventory.visible,
            extras: vec![],
        })
    }
}

pub fn retain_reference(
    report: &Path,
    identity: Identity,
    portable: bool,
    source: Option<&Path>,
    visit: impl FnOnce(&mut dyn FnMut(Row) -> Result<()>) -> Result<()>,
) -> Result<ArtifactReference> {
    if !portable
        && let Some(reference) = ArtifactReference::existing::<Inventory>(report, &identity.key()?)?
    {
        let (inventory, _) = reference.load::<Inventory>(report)?;
        inventory.validate(&reference)?;
        ensure!(
            inventory.identity == identity,
            "Global projection Source or policy identity changed"
        );
        return Ok(reference);
    }
    if !portable
        && let Some(source) = source
        && let Some(reference) = super::preparation::import(source, report, &identity)?
    {
        return Ok(reference);
    }
    let key = identity.key()?;
    let build = |staging: &Path| {
        let mut builder = Builder::new(staging, identity);
        visit(&mut |row| builder.push(row))?;
        builder.finish()
    };
    if portable {
        ArtifactReference::retain_portable(report, key, build)
    } else {
        ArtifactReference::retain(report, key, build)
    }
}

impl RegularEvidence {
    pub fn from_live_snapshot(
        report: &Path,
        baseline: &RegularBaseline,
        snapshot: (usize, Vec<Change>),
        extras: Vec<Row>,
    ) -> Result<Self> {
        let (core_remaining, changes) = snapshot;
        let changed = changes
            .iter()
            .map(|change| (change.position, change.after))
            .collect::<BTreeMap<_, _>>();
        let remaining = core_remaining
            .checked_add(
                extras
                    .iter()
                    .filter(|row| changed.get(&row.position).copied().unwrap_or(row.visible))
                    .count(),
            )
            .context("Global visibility count overflow")?;
        let visible = baseline
            .visible
            .checked_add(extras.iter().filter(|row| row.visible).count())
            .context("Global visibility count overflow")?;
        let current = RegularBaseline {
            reference: baseline.reference.clone(),
            origin_report: baseline.origin_report.clone(),
            visible,
            extras,
        };
        Self::from_snapshot(report, &current, (remaining, changes))
    }

    #[cfg(test)]
    fn from_usage(report: &Path, baseline: &RegularBaseline, usage: &Usage) -> Result<Self> {
        Self::from_snapshot(report, baseline, usage.snapshot()?)
    }

    fn from_snapshot(
        report: &Path,
        baseline: &RegularBaseline,
        snapshot: (usize, Vec<Change>),
    ) -> Result<Self> {
        let (inventory, _) = baseline
            .reference
            .load::<Inventory>(&baseline.origin_report)?;
        inventory.validate(&baseline.reference)?;
        let reference = baseline.reference.stage::<Inventory>(
            &baseline.origin_report,
            report,
            |inventory, root, staging| inventory.stage(root, staging),
        )?;
        let (remaining, changes) = snapshot;
        let evidence = Self {
            inventory: reference,
            recorded: inventory
                .recorded
                .checked_add(baseline.extras.len())
                .context("Global inventory count overflow")?,
            baseline_visible: baseline.visible,
            remaining,
            changes,
            extras: baseline.extras.clone(),
        };
        evidence.load(report)?;
        Ok(evidence)
    }

    pub fn count(&self) -> Result<usize> {
        ensure!(
            self.remaining <= self.recorded && self.baseline_visible <= self.recorded,
            "invalid Global visibility counts"
        );
        Ok(self.remaining)
    }

    pub fn validate_protocol(&self, report: &Path, protocol: &str) -> Result<()> {
        let (inventory, _) = self.load(report)?;
        ensure!(
            inventory.identity.protocol == protocol,
            "Global inventory belongs to another protocol"
        );
        Ok(())
    }

    fn load(&self, report: &Path) -> Result<(Inventory, PathBuf)> {
        let (inventory, root) = self.inventory.load::<Inventory>(report)?;
        inventory.validate(&self.inventory)?;
        ensure!(
            self.extras
                .windows(2)
                .all(|pair| pair[0].position < pair[1].position)
                && self.extras.iter().all(|row| inventory
                    .identity
                    .layout
                    .get(row.position.section as usize)
                    .is_some_and(|boundary| row.position.index >= *boundary)),
            "Global session extras overlap the immutable inventory"
        );
        let baseline_visible = inventory
            .visible
            .checked_add(self.extras.iter().filter(|row| row.visible).count())
            .context("Global inventory count overflow")?;
        ensure!(
            Some(self.recorded) == inventory.recorded.checked_add(self.extras.len())
                && self.baseline_visible == baseline_visible
                && self
                    .changes
                    .windows(2)
                    .all(|pair| pair[0].position < pair[1].position),
            "Global visibility inventory or order changed"
        );
        let mut pages = BTreeMap::new();
        let mut visible = baseline_visible;
        for change in &self.changes {
            ensure!(
                change.before != change.after,
                "redundant Global visibility change"
            );
            if let Ok(index) = self
                .extras
                .binary_search_by_key(&change.position, |row| row.position)
            {
                ensure!(
                    self.extras[index].visible == change.before,
                    "Global extra visibility baseline changed"
                );
                visible = if change.after {
                    visible.checked_add(1)
                } else {
                    visible.checked_sub(1)
                }
                .context("Global visibility count overflow or underflow")?;
                continue;
            }
            let page = inventory.page_for_position(change.position)?;
            if let std::collections::btree_map::Entry::Vacant(entry) = pages.entry(page) {
                entry.insert(inventory.read_page(&root, page)?);
            }
            let rows = &pages[&page];
            let row = rows
                .binary_search_by_key(&change.position, |row| row.position)
                .ok()
                .map(|index| &rows[index])
                .context("Global visibility change does not identify a native row")?;
            ensure!(
                row.visible == change.before,
                "Global visibility baseline changed"
            );
            visible = if change.after {
                visible.checked_add(1)
            } else {
                visible.checked_sub(1)
            }
            .context("Global visibility count overflow or underflow")?;
        }
        ensure!(
            visible == self.remaining,
            "Global visibility changes do not match remaining count"
        );
        Ok((inventory, root))
    }

    pub fn read(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()> {
        cursor::read(self, report, offset, limit, items)
    }

    pub fn stage(&self, source: &Path, destination: &Path) -> Result<Self> {
        self.load(source)?;
        let inventory = self.inventory.stage::<Inventory>(
            source,
            destination,
            |inventory, root, staging| inventory.stage(root, staging),
        )?;
        Ok(Self {
            inventory,
            ..self.clone()
        })
    }
}
